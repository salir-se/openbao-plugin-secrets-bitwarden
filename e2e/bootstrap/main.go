// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

//go:build e2e

// Command bootstrap prepares the Bitwarden side of the end-to-end test
// environment (see docs/e2e.md). It is not part of the plugin and is only
// compiled with the `e2e` build tag.
//
// A Bitwarden-compatible server stores ciphertext only, so creating accounts,
// organizations and memberships is a client-side job: the client generates the
// keys, wraps them, and uploads the wrapped form. This program does the
// minimum of that against the server's public HTTP API to build the setup the
// README recommends:
//
//  1. Three accounts (PBKDF2-SHA256, RSA-2048 key pair each): a human Admin
//     who owns the organization, the sync account the plugin logs in as, and
//     a human Developer who only reads.
//  2. An organization created and owned by the Admin. The organization key is
//     64 random bytes, wrapped with the Admin's RSA public key (RSA-OAEP-SHA1,
//     cipher string type 4).
//  3. The collections, whose names are encrypted with the organization key.
//  4. The sync account as a member that can write to the collections, and the
//     Developer as a member with read-only access. The Admin invites each one and
//     confirms the membership by wrapping the organization key with that
//     member's public key.
//
// It prints one JSON object with the resulting IDs on stdout and is safe to
// run repeatedly.
//
// Configuration comes from the environment:
//
//	E2E_VW_URL                  base URL of the server, e.g. https://vaultwarden
//	E2E_ADMIN_EMAIL, E2E_ADMIN_PASSWORD     organization owner (the Admin)
//	E2E_SYNC_EMAIL, E2E_SYNC_PASSWORD       account the plugin uses
//	E2E_DEVELOPER_EMAIL, E2E_DEVELOPER_PASSWORD   read-only member (the Developer)
//	E2E_VW_ORG_NAME             organization name
//	E2E_VW_COLLECTIONS          comma-separated collection names; the first
//	                            one is created together with the organization
//	E2E_SYNC_MEMBER_TYPE        organization role of the sync account:
//	                            user (default), manager, admin or owner
//	E2E_SYNC_COLLECTION_ACCESS  its access to the collections: write
//	                            (default), manage, readonly or none
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP with SHA-1 is what the Bitwarden protocol uses for wrapped organization keys.
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	vaultwarden "github.com/salir-se/openbao-plugin-secrets-bitwarden"
)

const (
	// kdfIterations is the PBKDF2 iteration count the accounts are registered
	// with. It is Bitwarden's current default for new PBKDF2 accounts.
	kdfIterations = 600000

	// symKeyLen is the length of a Bitwarden symmetric key: 32 bytes for
	// AES-256-CBC followed by 32 bytes for HMAC-SHA256.
	symKeyLen = 64

	requestTimeout = 30 * time.Second

	// Membership states and roles as the organization API reports them.
	memberConfirmed = 2
	memberTypeOwner = 0
	memberTypeAdmin = 1
	memberTypeUser  = 2
	memberTypeMgr   = 3
)

// account is one fixture account.
type account struct {
	Email    string
	Password string
	Name     string
}

// collectionAccess is a member's access to every fixture collection.
type collectionAccess struct {
	Granted       bool
	ReadOnly      bool
	HidePasswords bool
	Manage        bool
}

// settings is the program's input, read from the environment.
type settings struct {
	URL         string
	Admin       account
	Sync        account
	Developer   account
	OrgName     string
	Collections []string
	SyncType    int
	SyncAccess  collectionAccess
}

// result is the JSON document printed on success.
type result struct {
	OrganizationID  string            `json:"organization_id"`
	Organization    string            `json:"organization"`
	Collections     map[string]string `json:"collections"`
	AdminUserID     string            `json:"admin_user_id"`
	SyncUserID      string            `json:"sync_user_id"`
	DeveloperUserID string            `json:"developer_user_id"`
	SyncMemberType  string            `json:"sync_member_type"`
	SyncAccess      string            `json:"sync_collection_access"`
}

// session is an authenticated API session of one account together with the
// keys needed to wrap and unwrap organization keys.
type session struct {
	baseURL     string
	http        *http.Client
	accessToken string
	userID      string
	privateKey  *rsa.PrivateKey
}

// symKey is a Bitwarden symmetric key split into its two halves.
type symKey struct {
	enc []byte
	mac []byte
}

func (k symKey) bytes() []byte {
	return append(append(make([]byte, 0, symKeyLen), k.enc...), k.mac...)
}

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap:", err)
		os.Exit(1)
	}
}

func run(stdout io.Writer) error {
	cfg, err := loadSettings()
	if err != nil {
		return err
	}

	ctx := context.Background()
	client := &http.Client{Timeout: requestTimeout}

	admin, err := ensureAccount(ctx, client, cfg.URL, cfg.Admin)
	if err != nil {
		return err
	}
	syncAcct, err := ensureAccount(ctx, client, cfg.URL, cfg.Sync)
	if err != nil {
		return err
	}
	developer, err := ensureAccount(ctx, client, cfg.URL, cfg.Developer)
	if err != nil {
		return err
	}

	orgID, orgKey, err := admin.ensureOrganization(ctx, cfg)
	if err != nil {
		return err
	}
	collections, err := admin.ensureCollections(ctx, cfg, orgID, orgKey)
	if err != nil {
		return err
	}

	readOnly := collectionAccess{Granted: true, ReadOnly: true}
	if err := admin.ensureMember(ctx, orgID, orgKey, cfg.Sync.Email, syncAcct.userID, cfg.SyncType, cfg.SyncAccess, collections); err != nil {
		return fmt.Errorf("sync account membership: %w", err)
	}
	if err := admin.ensureMember(ctx, orgID, orgKey, cfg.Developer.Email, developer.userID, memberTypeUser, readOnly, collections); err != nil {
		return fmt.Errorf("developer membership: %w", err)
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result{
		OrganizationID:  orgID,
		Organization:    cfg.OrgName,
		Collections:     collections,
		AdminUserID:     admin.userID,
		SyncUserID:      syncAcct.userID,
		DeveloperUserID: developer.userID,
		SyncMemberType:  envOr("E2E_SYNC_MEMBER_TYPE", "user"),
		SyncAccess:      envOr("E2E_SYNC_COLLECTION_ACCESS", "write"),
	})
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func loadAccount(prefix, name string) (account, error) {
	a := account{
		Email:    os.Getenv(prefix + "_EMAIL"),
		Password: os.Getenv(prefix + "_PASSWORD"),
		Name:     name,
	}
	if a.Email == "" || a.Password == "" {
		return account{}, fmt.Errorf("%s_EMAIL and %s_PASSWORD are required", prefix, prefix)
	}
	return a, nil
}

func loadSettings() (*settings, error) {
	cfg := &settings{
		URL:     strings.TrimRight(os.Getenv("E2E_VW_URL"), "/"),
		OrgName: os.Getenv("E2E_VW_ORG_NAME"),
	}
	for name := range strings.SplitSeq(os.Getenv("E2E_VW_COLLECTIONS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			cfg.Collections = append(cfg.Collections, name)
		}
	}
	switch {
	case cfg.URL == "":
		return nil, errors.New("E2E_VW_URL is required")
	case cfg.OrgName == "":
		return nil, errors.New("E2E_VW_ORG_NAME is required")
	case len(cfg.Collections) == 0:
		return nil, errors.New("E2E_VW_COLLECTIONS must name at least one collection")
	}

	var err error
	if cfg.Admin, err = loadAccount("E2E_ADMIN", "E2E Admin"); err != nil {
		return nil, err
	}
	if cfg.Sync, err = loadAccount("E2E_SYNC", "E2E Sync Bot"); err != nil {
		return nil, err
	}
	if cfg.Developer, err = loadAccount("E2E_DEVELOPER", "E2E Developer"); err != nil {
		return nil, err
	}

	switch t := envOr("E2E_SYNC_MEMBER_TYPE", "user"); t {
	case "owner":
		cfg.SyncType = memberTypeOwner
	case "admin":
		cfg.SyncType = memberTypeAdmin
	case "user":
		cfg.SyncType = memberTypeUser
	case "manager":
		cfg.SyncType = memberTypeMgr
	default:
		return nil, fmt.Errorf("E2E_SYNC_MEMBER_TYPE %q: want owner, admin, manager or user", t)
	}
	switch a := envOr("E2E_SYNC_COLLECTION_ACCESS", "write"); a {
	case "manage":
		cfg.SyncAccess = collectionAccess{Granted: true, Manage: true}
	case "write":
		cfg.SyncAccess = collectionAccess{Granted: true}
	case "readonly":
		cfg.SyncAccess = collectionAccess{Granted: true, ReadOnly: true}
	case "none":
		cfg.SyncAccess = collectionAccess{}
	default:
		return nil, fmt.Errorf("E2E_SYNC_COLLECTION_ACCESS %q: want manage, write, readonly or none", a)
	}
	return cfg, nil
}

// ensureAccount returns a logged-in session for the account, registering it
// first when the login fails. Login goes first because the server does not say
// why a registration was refused.
func ensureAccount(ctx context.Context, client *http.Client, baseURL string, a account) (*session, error) {
	s := &session{baseURL: baseURL, http: client}
	if err := s.login(ctx, a); err != nil {
		if regErr := s.register(ctx, a); regErr != nil {
			return nil, fmt.Errorf("%s: login failed (%w) and registration failed: %w", a.Email, err, regErr)
		}
		if err := s.login(ctx, a); err != nil {
			return nil, fmt.Errorf("%s: login after registration: %w", a.Email, err)
		}
	}

	var profile struct {
		ID string `json:"id"`
	}
	if err := s.doJSON(ctx, http.MethodGet, "/api/accounts/profile", nil, &profile); err != nil {
		return nil, fmt.Errorf("%s: reading profile: %w", a.Email, err)
	}
	if profile.ID == "" {
		return nil, fmt.Errorf("%s: profile has no id", a.Email)
	}
	s.userID = profile.ID
	return s, nil
}

// register creates the account. The client generates the user key and an RSA
// key pair; the server receives the user key wrapped with the stretched master
// key and the private key wrapped with the user key.
func (s *session) register(ctx context.Context, a account) error {
	masterKey, encKey, macKey, err := vaultwarden.DeriveKeys(a.Email, a.Password, kdfIterations)
	if err != nil {
		return fmt.Errorf("deriving keys: %w", err)
	}

	userKey, err := newSymKey()
	if err != nil {
		return err
	}
	wrappedUserKey, err := vaultwarden.EncryptCipherString(string(userKey.bytes()), encKey, macKey)
	if err != nil {
		return fmt.Errorf("wrapping user key: %w", err)
	}

	publicKey, wrappedPrivateKey, err := newWrappedRSAKeyPair(userKey)
	if err != nil {
		return err
	}

	body := map[string]any{
		"email":              a.Email,
		"name":               a.Name,
		"masterPasswordHash": vaultwarden.ComputePasswordHash(masterKey, a.Password),
		"masterPasswordHint": "",
		"key":                wrappedUserKey,
		"kdf":                0, // PBKDF2-SHA256
		"kdfIterations":      kdfIterations,
		"keys": map[string]string{
			"publicKey":           publicKey,
			"encryptedPrivateKey": wrappedPrivateKey,
		},
	}
	return s.doJSON(ctx, http.MethodPost, "/identity/accounts/register", body, nil)
}

// login authenticates with the master password hash and unwraps the user key
// and the RSA private key from the response.
func (s *session) login(ctx context.Context, a account) error {
	masterKey, encKey, macKey, err := vaultwarden.DeriveKeys(a.Email, a.Password, kdfIterations)
	if err != nil {
		return fmt.Errorf("deriving keys: %w", err)
	}

	form := url.Values{
		"grant_type":       {"password"},
		"username":         {a.Email},
		"password":         {vaultwarden.ComputePasswordHash(masterKey, a.Password)},
		"scope":            {"api offline_access"},
		"client_id":        {"cli"},
		"deviceType":       {"14"},
		"deviceIdentifier": {"e2e00000-0000-4000-8000-000000000001"},
		"deviceName":       {"e2e-bootstrap"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/identity/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("building login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp struct {
		AccessToken string `json:"access_token"`
		Key         string `json:"Key"`
		PrivateKey  string `json:"PrivateKey"`
	}
	if err := s.send(req, &resp); err != nil {
		return err
	}
	if resp.AccessToken == "" || resp.Key == "" || resp.PrivateKey == "" {
		return errors.New("login response lacks access_token, Key or PrivateKey")
	}

	userEnc, userMac, err := vaultwarden.DecryptSymmetricKeyRaw(resp.Key, encKey, macKey)
	if err != nil {
		return fmt.Errorf("unwrapping user key: %w", err)
	}
	privateKey, err := vaultwarden.DecryptPrivateKey(resp.PrivateKey, userEnc, userMac)
	if err != nil {
		return fmt.Errorf("unwrapping private key: %w", err)
	}

	s.accessToken = resp.AccessToken
	s.privateKey = privateKey
	return nil
}

// ensureOrganization returns the ID and key of the organization, creating it
// when the account is not yet a member of one with the configured name.
func (s *session) ensureOrganization(ctx context.Context, cfg *settings) (orgID string, orgKey symKey, err error) {
	var sync struct {
		Profile struct {
			Organizations []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Key  string `json:"key"`
			} `json:"organizations"`
		} `json:"profile"`
	}
	if err := s.doJSON(ctx, http.MethodGet, "/api/sync?excludeDomains=true", nil, &sync); err != nil {
		return "", symKey{}, fmt.Errorf("reading vault: %w", err)
	}

	for _, org := range sync.Profile.Organizations {
		if org.Name != cfg.OrgName {
			continue
		}
		raw, err := vaultwarden.DecryptRSACipherString(org.Key, s.privateKey)
		if err != nil {
			return "", symKey{}, fmt.Errorf("unwrapping key of organization %s: %w", org.ID, err)
		}
		if len(raw) != symKeyLen {
			return "", symKey{}, fmt.Errorf("organization %s: key is %d bytes, want %d", org.ID, len(raw), symKeyLen)
		}
		return org.ID, symKey{enc: raw[:32], mac: raw[32:]}, nil
	}

	orgKey, err = newSymKey()
	if err != nil {
		return "", symKey{}, err
	}

	// The organization key travels wrapped with the owner's RSA public key.
	wrappedOrgKey, err := wrapWithRSA(&s.privateKey.PublicKey, orgKey.bytes())
	if err != nil {
		return "", symKey{}, err
	}

	collectionName, err := vaultwarden.EncryptCipherString(cfg.Collections[0], orgKey.enc, orgKey.mac)
	if err != nil {
		return "", symKey{}, fmt.Errorf("encrypting collection name: %w", err)
	}

	// An organization has its own RSA key pair; the private half is wrapped
	// with the organization key.
	publicKey, wrappedPrivateKey, err := newWrappedRSAKeyPair(orgKey)
	if err != nil {
		return "", symKey{}, err
	}

	body := map[string]any{
		"name":           cfg.OrgName,
		"billingEmail":   cfg.Admin.Email,
		"collectionName": collectionName,
		"key":            wrappedOrgKey,
		"keys": map[string]string{
			"publicKey":           publicKey,
			"encryptedPrivateKey": wrappedPrivateKey,
		},
		"planType": 0,
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := s.doJSON(ctx, http.MethodPost, "/api/organizations", body, &created); err != nil {
		return "", symKey{}, fmt.Errorf("creating organization: %w", err)
	}
	if created.ID == "" {
		return "", symKey{}, errors.New("creating organization: response has no id")
	}
	return created.ID, orgKey, nil
}

// ensureCollections makes sure every configured collection exists and returns
// a map of collection name to ID.
func (s *session) ensureCollections(ctx context.Context, cfg *settings, orgID string, orgKey symKey) (map[string]string, error) {
	base := "/api/organizations/" + url.PathEscape(orgID)

	var existing struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := s.doJSON(ctx, http.MethodGet, base+"/collections", nil, &existing); err != nil {
		return nil, fmt.Errorf("listing collections: %w", err)
	}

	byName := make(map[string]string, len(existing.Data))
	for _, c := range existing.Data {
		name, err := vaultwarden.DecryptCipherString(c.Name, orgKey.enc, orgKey.mac)
		if err != nil {
			return nil, fmt.Errorf("decrypting name of collection %s: %w", c.ID, err)
		}
		byName[name] = c.ID
	}

	out := make(map[string]string, len(cfg.Collections))
	for _, name := range cfg.Collections {
		if id, ok := byName[name]; ok {
			out[name] = id
			continue
		}

		encName, err := vaultwarden.EncryptCipherString(name, orgKey.enc, orgKey.mac)
		if err != nil {
			return nil, fmt.Errorf("encrypting collection name: %w", err)
		}
		body := map[string]any{
			"name":   encName,
			"groups": []any{},
			"users":  []any{},
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := s.doJSON(ctx, http.MethodPost, base+"/collections", body, &created); err != nil {
			return nil, fmt.Errorf("creating collection %q: %w", name, err)
		}
		if created.ID == "" {
			return nil, fmt.Errorf("creating collection %q: response has no id", name)
		}
		out[name] = created.ID
	}
	return out, nil
}

// ensureMember makes the account a confirmed member of the organization with
// the given role and collection access. An account that is already a member is
// left as it is, apart from being confirmed when it is not yet.
func (s *session) ensureMember(ctx context.Context, orgID string, orgKey symKey, email, userID string, memberType int, access collectionAccess, collections map[string]string) error {
	base := "/api/organizations/" + url.PathEscape(orgID) + "/users"

	type member struct {
		ID     string `json:"id"`
		UserID string `json:"userId"`
		Status int    `json:"status"`
	}
	find := func() (*member, error) {
		var list struct {
			Data []member `json:"data"`
		}
		if err := s.doJSON(ctx, http.MethodGet, base, nil, &list); err != nil {
			return nil, fmt.Errorf("listing members: %w", err)
		}
		for i := range list.Data {
			if list.Data[i].UserID == userID {
				return &list.Data[i], nil
			}
		}
		return nil, nil
	}

	m, err := find()
	if err != nil {
		return err
	}
	if m == nil {
		grants := []map[string]any{}
		if access.Granted {
			for _, id := range collections {
				grants = append(grants, map[string]any{
					"id":            id,
					"readOnly":      access.ReadOnly,
					"hidePasswords": access.HidePasswords,
					"manage":        access.Manage,
				})
			}
		}
		invite := map[string]any{
			"emails":               []string{email},
			"type":                 memberType,
			"collections":          grants,
			"groups":               []any{},
			"accessSecretsManager": false,
		}
		if err := s.doJSON(ctx, http.MethodPost, base+"/invite", invite, nil); err != nil {
			return fmt.Errorf("inviting %s: %w", email, err)
		}
		if m, err = find(); err != nil {
			return err
		}
		if m == nil {
			return fmt.Errorf("%s is not listed as a member after the invitation", email)
		}
	}
	if m.Status == memberConfirmed {
		return nil
	}

	// Confirming a member means handing them the organization key, wrapped
	// with their own RSA public key so that only they can unwrap it.
	var pub struct {
		PublicKey string `json:"publicKey"`
	}
	if err := s.doJSON(ctx, http.MethodGet, "/api/users/"+url.PathEscape(userID)+"/public-key", nil, &pub); err != nil {
		return fmt.Errorf("fetching public key of %s: %w", email, err)
	}
	der, err := base64.StdEncoding.DecodeString(pub.PublicKey)
	if err != nil {
		return fmt.Errorf("decoding public key of %s: %w", email, err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("parsing public key of %s: %w", email, err)
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key of %s is %T, want RSA", email, parsed)
	}
	wrapped, err := wrapWithRSA(rsaPub, orgKey.bytes())
	if err != nil {
		return err
	}
	if err := s.doJSON(ctx, http.MethodPost, base+"/"+url.PathEscape(m.ID)+"/confirm", map[string]string{"key": wrapped}, nil); err != nil {
		return fmt.Errorf("confirming %s: %w", email, err)
	}
	return nil
}

// doJSON sends an optional JSON body and decodes a JSON response into out
// when out is not nil.
func (s *session) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.accessToken)
	}
	return s.send(req, out)
}

// send executes req and decodes a 2xx JSON response into out when out is not
// nil. Any other status is returned as an error that carries the body.
func (s *session) send(req *http.Request, out any) error {
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("%s %s: reading response: %w", req.Method, req.URL.Path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s %s: decoding response: %w", req.Method, req.URL.Path, err)
	}
	return nil
}

// newSymKey returns a fresh random 64-byte symmetric key.
func newSymKey() (symKey, error) {
	raw := make([]byte, symKeyLen)
	if _, err := rand.Read(raw); err != nil {
		return symKey{}, fmt.Errorf("generating key: %w", err)
	}
	return symKey{enc: raw[:32], mac: raw[32:]}, nil
}

// wrapWithRSA encrypts data for the holder of the matching private key and
// returns it as a type-4 cipher string (RSA-2048-OAEP-SHA1).
func wrapWithRSA(pub *rsa.PublicKey, data []byte) (string, error) {
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, data, nil) //nolint:gosec // SHA-1 here is mandated by the Bitwarden protocol (cipher string type 4).
	if err != nil {
		return "", fmt.Errorf("wrapping key with RSA: %w", err)
	}
	return "4." + base64.StdEncoding.EncodeToString(wrapped), nil
}

// newWrappedRSAKeyPair generates an RSA-2048 key pair and returns the public
// key (SubjectPublicKeyInfo DER, base64) and the private key (PKCS#8 DER)
// encrypted with the given symmetric key.
func newWrappedRSAKeyPair(wrapWith symKey) (publicKey, wrappedPrivateKey string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generating RSA key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("encoding public key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("encoding private key: %w", err)
	}
	wrappedPrivateKey, err = vaultwarden.EncryptCipherString(string(privDER), wrapWith.enc, wrapWith.mac)
	if err != nil {
		return "", "", fmt.Errorf("wrapping private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pubDER), wrappedPrivateKey, nil
}
