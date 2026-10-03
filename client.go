// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Vaultwarden HTTP client implementing the Bitwarden-compatible API.
//
// This client handles:
//   - Prelogin (KDF parameter discovery)
//   - OAuth2 token-based authentication
//   - Token refresh
//   - CRUD operations on cipher items
//   - Organization cipher management
//   - Cipher name decryption for search operations

package vaultwarden

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
)

// deviceIdentifier is a stable UUID used for all client sessions.
// In production, this could be derived from the OpenBao node ID.
var deviceIdentifier = uuid.NewSHA1(uuid.NameSpaceURL, []byte("openbao-plugin-secrets-bitwarden")).String()

// VaultwardenConfig holds the configuration for connecting to Vaultwarden.
type VaultwardenConfig struct {
	URL            string `json:"url"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	OrganizationID string `json:"organization_id"`
}

// VaultwardenClient is a thread-safe HTTP client for the Vaultwarden/Bitwarden API.
type VaultwardenClient struct {
	baseURL      string
	email        string
	accessToken  string
	refreshToken string
	symEncKey    []byte                // user's symmetric encryption key (32 bytes)
	symMacKey    []byte                // user's symmetric MAC key (32 bytes)
	privateKey   *rsa.PrivateKey       // user's RSA private key (for org key decryption)
	orgKeys      map[string]orgKeyPair // org ID -> decrypted org keys
	httpClient   *http.Client
	logger       hclog.Logger
	mu           sync.RWMutex
}

// orgKeyPair holds the decrypted encryption and MAC keys for an organization.
type orgKeyPair struct {
	encKey []byte
	macKey []byte
}

// preloginRequest is the request body for /identity/accounts/prelogin.
type preloginRequest struct {
	Email string `json:"email"`
}

// preloginResponse is the response from /identity/accounts/prelogin.
type preloginResponse struct {
	KDF            int `json:"kdf"`
	KDFIterations  int `json:"kdfIterations"`
	KDFMemory      int `json:"kdfMemory,omitempty"`
	KDFParallelism int `json:"kdfParallelism,omitempty"`
}

// loginResponse is the response from /identity/connect/token.
type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Key          string `json:"Key"`        // encrypted symmetric key
	PrivateKey   string `json:"PrivateKey"` // encrypted private key
}

// syncResponse is the response from /api/sync.
type syncResponse struct {
	Profile syncProfile      `json:"profile"`
	Ciphers []CipherResponse `json:"ciphers"`
}

// syncProfile contains profile data including organization info.
type syncProfile struct {
	ID            string             `json:"id"`
	Email         string             `json:"email"`
	Organizations []syncOrganization `json:"organizations"`
}

// syncOrganization contains organization data from the sync response.
type syncOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"` // encrypted org key
}

// CipherRequest is the request body for creating/updating a cipher.
type CipherRequest struct {
	Type           int                   `json:"type"`
	Name           string                `json:"name"`
	Notes          string                `json:"notes,omitempty"`
	OrganizationID string                `json:"organizationId,omitempty"`
	CollectionIDs  []string              `json:"collectionIds,omitempty"`
	FolderID       string                `json:"folderId,omitempty"`
	Login          *CipherLoginData      `json:"login,omitempty"`
	SecureNote     *CipherSecureNoteData `json:"secureNote,omitempty"`
	Card           *CipherCardData       `json:"card,omitempty"`
	Identity       *CipherIdentityData   `json:"identity,omitempty"`
	Fields         []CipherFieldData     `json:"fields,omitempty"`
}

// CipherLoginData holds login-type cipher data.
type CipherLoginData struct {
	URIs     []CipherURI `json:"uris,omitempty"`
	Username string      `json:"username,omitempty"`
	Password string      `json:"password,omitempty"`
}

// CipherURI holds a URI entry for a login cipher.
type CipherURI struct {
	URI   string `json:"uri"`
	Match *int   `json:"match"`
}

// CipherFieldData holds a custom field for a cipher.
type CipherFieldData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"` // 0=text, 1=hidden, 2=boolean
}

// CipherSecureNoteData holds secure note cipher data.
type CipherSecureNoteData struct {
	Type int `json:"type"` // always 0 for generic
}

// CipherCardData holds card-type cipher data.
type CipherCardData struct {
	CardholderName string `json:"cardholderName,omitempty"`
	Brand          string `json:"brand,omitempty"`
	Number         string `json:"number,omitempty"`
	ExpMonth       string `json:"expMonth,omitempty"`
	ExpYear        string `json:"expYear,omitempty"`
	Code           string `json:"code,omitempty"`
}

// CipherIdentityData holds identity-type cipher data.
type CipherIdentityData struct {
	Title          string `json:"title,omitempty"`
	FirstName      string `json:"firstName,omitempty"`
	MiddleName     string `json:"middleName,omitempty"`
	LastName       string `json:"lastName,omitempty"`
	Email          string `json:"email,omitempty"`
	Phone          string `json:"phone,omitempty"`
	Company        string `json:"company,omitempty"`
	SSN            string `json:"ssn,omitempty"`
	Username       string `json:"username,omitempty"`
	PassportNumber string `json:"passportNumber,omitempty"`
	LicenseNumber  string `json:"licenseNumber,omitempty"`
	Address1       string `json:"address1,omitempty"`
	Address2       string `json:"address2,omitempty"`
	Address3       string `json:"address3,omitempty"`
	City           string `json:"city,omitempty"`
	State          string `json:"state,omitempty"`
	PostalCode     string `json:"postalCode,omitempty"`
	Country        string `json:"country,omitempty"`
}

// CipherResponse is the response from cipher CRUD operations.
type CipherResponse struct {
	ID             string            `json:"id"`
	Type           int               `json:"type"`
	Name           string            `json:"name"`
	Notes          string            `json:"notes"`
	OrganizationID string            `json:"organizationId"`
	CollectionIDs  []string          `json:"collectionIds"`
	RevisionDate   string            `json:"revisionDate"`
	Login          *CipherLoginData  `json:"login,omitempty"`
	Fields         []CipherFieldData `json:"fields,omitempty"`
}

// orgCipherCreateRequest wraps a cipher with collection IDs for org cipher creation.
type orgCipherCreateRequest struct {
	Cipher        CipherRequest `json:"cipher"`
	CollectionIDs []string      `json:"collectionIds"`
}

// NewClient creates a new VaultwardenClient and authenticates with the server.
func NewClient(config *VaultwardenConfig, logger hclog.Logger) (*VaultwardenClient, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("vaultwarden URL is required")
	}
	if config.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if config.Password == "" {
		return nil, fmt.Errorf("master password is required")
	}

	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	c := &VaultwardenClient{
		baseURL: strings.TrimRight(config.URL, "/"),
		email:   config.Email,
		orgKeys: make(map[string]orgKeyPair),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}

	if err := c.Login(config.Email, config.Password); err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	return c, nil
}

// Prelogin retrieves the KDF parameters for the given email address.
func (c *VaultwardenClient) Prelogin(email string) (kdfType int, kdfIterations int, err error) {
	body, err := json.Marshal(preloginRequest{Email: email})
	if err != nil {
		return 0, 0, fmt.Errorf("marshaling prelogin request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/identity/accounts/prelogin",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return 0, 0, fmt.Errorf("prelogin request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("prelogin returned status %d", resp.StatusCode)
	}

	var preloginResp preloginResponse
	if err := json.NewDecoder(resp.Body).Decode(&preloginResp); err != nil {
		return 0, 0, fmt.Errorf("decoding prelogin response: %w", err)
	}

	return preloginResp.KDF, preloginResp.KDFIterations, nil
}

// Login authenticates to Vaultwarden, derives encryption keys, and decrypts
// the user's symmetric key.
func (c *VaultwardenClient) Login(email, masterPassword string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logger.Info("authenticating to Vaultwarden", "email", email)

	// Step 1: Get KDF parameters.
	kdfType, kdfIterations, err := c.Prelogin(email)
	if err != nil {
		return fmt.Errorf("prelogin: %w", err)
	}

	if kdfType != 0 {
		return fmt.Errorf("unsupported KDF type: %d (only PBKDF2 / type 0 is supported)", kdfType)
	}

	c.logger.Debug("KDF parameters", "type", kdfType, "iterations", kdfIterations)

	// Step 2: Derive keys.
	masterKey, encKey, macKey, err := DeriveKeys(email, masterPassword, kdfIterations)
	if err != nil {
		return fmt.Errorf("deriving keys: %w", err)
	}

	// Step 3: Compute password hash for authentication.
	passwordHash := ComputePasswordHash(masterKey, masterPassword)

	// Step 4: Authenticate via OAuth2 token endpoint.
	formData := url.Values{
		"grant_type":       {"password"},
		"username":         {email},
		"password":         {passwordHash},
		"scope":            {"api offline_access"},
		"client_id":        {"cli"},
		"deviceType":       {"14"},
		"deviceIdentifier": {deviceIdentifier},
		"deviceName":       {"openbao-plugin"},
	}

	resp, err := c.httpClient.PostForm(c.baseURL+"/identity/connect/token", formData)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var loginResp loginResponse
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return fmt.Errorf("decoding login response: %w", err)
	}

	c.accessToken = loginResp.AccessToken
	c.refreshToken = loginResp.RefreshToken

	// Step 5: Decrypt the user's symmetric key.
	symEncKey, symMacKey, err := DecryptSymmetricKeyRaw(loginResp.Key, encKey, macKey)
	if err != nil {
		return fmt.Errorf("decrypting symmetric key: %w", err)
	}

	c.symEncKey = symEncKey
	c.symMacKey = symMacKey

	// Step 6: Decrypt the user's RSA private key (needed for org key decryption).
	if loginResp.PrivateKey != "" {
		privKey, err := DecryptPrivateKey(loginResp.PrivateKey, symEncKey, symMacKey)
		if err != nil {
			c.logger.Warn("failed to decrypt RSA private key (org sync will not work)", "error", err)
		} else {
			c.privateKey = privKey
			c.logger.Debug("decrypted RSA private key")
		}
	}

	c.logger.Info("authentication successful")
	return nil
}

// RefreshAuth refreshes the access token using the refresh token.
func (c *VaultwardenClient) RefreshAuth() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.refreshToken},
		"client_id":     {"cli"},
	}

	resp, err := c.httpClient.PostForm(c.baseURL+"/identity/connect/token", formData)
	if err != nil {
		return fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("refresh returned status %d: %s", resp.StatusCode, string(body))
	}

	var loginResp loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return fmt.Errorf("decoding refresh response: %w", err)
	}

	c.accessToken = loginResp.AccessToken
	if loginResp.RefreshToken != "" {
		c.refreshToken = loginResp.RefreshToken
	}

	c.logger.Debug("token refreshed successfully")
	return nil
}

// GetEncryptionKeys returns the user's symmetric encryption keys.
// For organization ciphers, use GetOrgEncryptionKeys instead.
func (c *VaultwardenClient) GetEncryptionKeys() (encKey, macKey []byte) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.symEncKey, c.symMacKey
}

// Encrypt encrypts plaintext using the user's symmetric key and returns a CipherString.
func (c *VaultwardenClient) Encrypt(plaintext string) (string, error) {
	encKey, macKey := c.GetEncryptionKeys()
	return EncryptCipherString(plaintext, encKey, macKey)
}

// GetOrgEncryptionKeys returns the organization's encryption keys.
// If not cached, it fetches them via /api/sync.
func (c *VaultwardenClient) GetOrgEncryptionKeys(orgID string) (encKey, macKey []byte, err error) {
	c.mu.RLock()
	if kp, ok := c.orgKeys[orgID]; ok {
		c.mu.RUnlock()
		return kp.encKey, kp.macKey, nil
	}
	c.mu.RUnlock()

	// Fetch org keys via sync.
	if err := c.fetchOrgKeys(); err != nil {
		return nil, nil, fmt.Errorf("fetching org keys: %w", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	kp, ok := c.orgKeys[orgID]
	if !ok {
		return nil, nil, fmt.Errorf("organization %s not found or no key available", orgID)
	}

	return kp.encKey, kp.macKey, nil
}

// fetchOrgKeys fetches and decrypts organization keys from the sync endpoint.
func (c *VaultwardenClient) fetchOrgKeys() error {
	syncResp, err := c.doSync()
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, org := range syncResp.Profile.Organizations {
		if org.Key == "" {
			continue
		}

		// Org keys can be encrypted with either:
		//   - Type 2 (AES-256-CBC): encrypted with user's symmetric key
		//   - Type 4 (RSA-2048-OAEP-SHA1): encrypted with user's RSA public key
		var orgKeyRaw []byte
		if strings.HasPrefix(org.Key, "4.") {
			// RSA-encrypted org key — requires the user's private key.
			if c.privateKey == nil {
				c.logger.Warn("org key is RSA-encrypted but no private key available", "org_id", org.ID)
				continue
			}
			orgKeyRaw, err = DecryptRSACipherString(org.Key, c.privateKey)
			if err != nil {
				c.logger.Warn("failed to decrypt RSA org key", "org_id", org.ID, "error", err)
				continue
			}
		} else {
			// AES-encrypted org key.
			orgKeyRaw, err = decryptCipherStringRaw(org.Key, c.symEncKey, c.symMacKey)
			if err != nil {
				c.logger.Warn("failed to decrypt org key", "org_id", org.ID, "error", err)
				continue
			}
		}

		if len(orgKeyRaw) != 64 {
			c.logger.Warn("unexpected org key length", "org_id", org.ID, "length", len(orgKeyRaw))
			continue
		}

		c.orgKeys[org.ID] = orgKeyPair{
			encKey: orgKeyRaw[:32],
			macKey: orgKeyRaw[32:],
		}
		c.logger.Debug("cached org encryption keys", "org_id", org.ID)
	}

	return nil
}

// doSync performs a full vault sync and returns the response.
func (c *VaultwardenClient) doSync() (*syncResponse, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/sync", nil)
	if err != nil {
		return nil, fmt.Errorf("creating sync request: %w", err)
	}

	c.mu.RLock()
	c.setAuthHeader(req)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sync request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Try to refresh and retry.
		if err := c.RefreshAuth(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
		c.mu.RLock()
		c.setAuthHeader(req)
		c.mu.RUnlock()
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("sync request after refresh failed: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sync returned status %d: %s", resp.StatusCode, string(body))
	}

	var syncResp syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return nil, fmt.Errorf("decoding sync response: %w", err)
	}

	return &syncResp, nil
}

// CreateCipher creates a new cipher in the user's personal vault.
func (c *VaultwardenClient) CreateCipher(cipher *CipherRequest) (*CipherResponse, error) {
	return c.doJSON("POST", "/api/ciphers", cipher)
}

// CreateOrgCipher creates a cipher in an organization with collection assignments.
func (c *VaultwardenClient) CreateOrgCipher(cipher *CipherRequest, collectionIDs []string) (*CipherResponse, error) {
	reqBody := orgCipherCreateRequest{
		Cipher:        *cipher,
		CollectionIDs: collectionIDs,
	}

	return c.doJSON("POST", "/api/ciphers/create", &reqBody)
}

// UpdateCipher updates an existing cipher by ID.
func (c *VaultwardenClient) UpdateCipher(id string, cipher *CipherRequest) (*CipherResponse, error) {
	return c.doJSON("PUT", "/api/ciphers/"+id, cipher)
}

// UpdateOrgCipher updates an organization-owned cipher using the admin endpoint.
// Org ciphers have no user_uuid, so the standard PUT /api/ciphers/<id> endpoint
// cannot match ownership. The admin endpoint checks org membership instead.
func (c *VaultwardenClient) UpdateOrgCipher(id string, cipher *CipherRequest) (*CipherResponse, error) {
	return c.doJSON("PUT", "/api/ciphers/"+id+"/admin", cipher)
}

// DeleteOrgCipher permanently deletes an organization-owned cipher by ID.
// Uses the admin endpoint which checks org membership instead of user ownership.
func (c *VaultwardenClient) DeleteOrgCipher(id string) error {
	return c.deleteCipher(id, true)
}

// DeleteCipher permanently deletes a cipher by ID.
func (c *VaultwardenClient) DeleteCipher(id string) error {
	return c.deleteCipher(id, false)
}

func (c *VaultwardenClient) deleteCipher(id string, admin bool) error {
	path := "/api/ciphers/" + id
	if admin {
		path += "/admin"
	}
	req, err := http.NewRequest("DELETE", c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("creating delete request: %w", err)
	}

	c.mu.RLock()
	c.setAuthHeader(req)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		if err := c.RefreshAuth(); err != nil {
			return fmt.Errorf("token refresh failed: %w", err)
		}
		c.mu.RLock()
		c.setAuthHeader(req)
		c.mu.RUnlock()
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("delete request after refresh failed: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetCipher retrieves a cipher by ID.
func (c *VaultwardenClient) GetCipher(id string) (*CipherResponse, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/ciphers/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("creating get request: %w", err)
	}

	c.mu.RLock()
	c.setAuthHeader(req)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		if err := c.RefreshAuth(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
		c.mu.RLock()
		c.setAuthHeader(req)
		c.mu.RUnlock()
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("get request after refresh failed: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get cipher returned status %d: %s", resp.StatusCode, string(body))
	}

	var cipherResp CipherResponse
	if err := json.NewDecoder(resp.Body).Decode(&cipherResp); err != nil {
		return nil, fmt.Errorf("decoding cipher response: %w", err)
	}

	return &cipherResp, nil
}

// ListCiphers lists all ciphers via the sync endpoint.
func (c *VaultwardenClient) ListCiphers() ([]CipherResponse, error) {
	syncResp, err := c.doSync()
	if err != nil {
		return nil, err
	}
	return syncResp.Ciphers, nil
}

// FindCipherByName finds a cipher by decrypted name in a specific organization.
// It uses the organization's encryption keys to decrypt cipher names.
func (c *VaultwardenClient) FindCipherByName(name, orgID string) (*CipherResponse, error) {
	ciphers, err := c.ListCiphers()
	if err != nil {
		return nil, fmt.Errorf("listing ciphers: %w", err)
	}

	// Get the appropriate encryption keys.
	var encKey, macKey []byte
	if orgID != "" {
		encKey, macKey, err = c.GetOrgEncryptionKeys(orgID)
		if err != nil {
			return nil, fmt.Errorf("getting org encryption keys: %w", err)
		}
	} else {
		encKey, macKey = c.GetEncryptionKeys()
	}

	for i := range ciphers {
		cipher := &ciphers[i]

		// Filter by org first (cheap).
		if orgID != "" && cipher.OrganizationID != orgID {
			continue
		}

		// Decrypt the cipher name.
		decryptedName, err := DecryptCipherString(cipher.Name, encKey, macKey)
		if err != nil {
			c.logger.Warn("failed to decrypt cipher name", "cipher_id", cipher.ID, "error", err)
			continue
		}

		if decryptedName == name {
			return cipher, nil
		}
	}

	return nil, nil // not found
}

// FindAllCiphersByName finds ALL ciphers matching a decrypted name in an organization.
// Returns all matches for deduplication purposes. If no matches, returns empty slice.
func (c *VaultwardenClient) FindAllCiphersByName(name, orgID string) ([]*CipherResponse, error) {
	ciphers, err := c.ListCiphers()
	if err != nil {
		return nil, fmt.Errorf("listing ciphers: %w", err)
	}

	var encKey, macKey []byte
	if orgID != "" {
		encKey, macKey, err = c.GetOrgEncryptionKeys(orgID)
		if err != nil {
			return nil, fmt.Errorf("getting org encryption keys: %w", err)
		}
	} else {
		encKey, macKey = c.GetEncryptionKeys()
	}

	var matches []*CipherResponse
	for i := range ciphers {
		cipher := &ciphers[i]

		if orgID != "" && cipher.OrganizationID != orgID {
			continue
		}

		decryptedName, err := DecryptCipherString(cipher.Name, encKey, macKey)
		if err != nil {
			c.logger.Warn("failed to decrypt cipher name", "cipher_id", cipher.ID, "error", err)
			continue
		}

		if decryptedName == name {
			matches = append(matches, cipher)
		}
	}

	return matches, nil
}

// CollectionResponse is the response from collection endpoints.
type CollectionResponse struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"` // encrypted
	ExternalID     string `json:"externalId,omitempty"`
}

// collectionsListResponse wraps the paginated collection list.
type collectionsListResponse struct {
	Data []CollectionResponse `json:"data"`
}

// FolderResponse is the response from folder endpoints.
type FolderResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"` // encrypted
	RevisionDate string `json:"revisionDate"`
}

// foldersListResponse wraps the paginated folder list.
type foldersListResponse struct {
	Data []FolderResponse `json:"data"`
}

// cipherCollectionsRequest is the body for updating cipher collection assignments.
type cipherCollectionsRequest struct {
	CollectionIDs []string `json:"collectionIds"`
}

// ListOrgCollections lists all collections in an organization.
func (c *VaultwardenClient) ListOrgCollections(orgID string) ([]CollectionResponse, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/organizations/"+orgID+"/collections", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	c.mu.RLock()
	c.setAuthHeader(req)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		if err := c.RefreshAuth(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
		c.mu.RLock()
		c.setAuthHeader(req)
		c.mu.RUnlock()
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request after refresh failed: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list collections returned status %d: %s", resp.StatusCode, string(body))
	}

	var listResp collectionsListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return listResp.Data, nil
}

// UpdateCipherCollections updates the collection assignments for a cipher.
func (c *VaultwardenClient) UpdateCipherCollections(cipherID string, collectionIDs []string, admin bool) error {
	path := "/api/ciphers/" + cipherID + "/collections"
	if admin {
		path += "/admin"
	}

	body := cipherCollectionsRequest{CollectionIDs: collectionIDs}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest("PUT", c.baseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	c.mu.RLock()
	c.setAuthHeader(req)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		if err := c.RefreshAuth(); err != nil {
			return fmt.Errorf("token refresh failed: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(jsonBody))
		c.mu.RLock()
		c.setAuthHeader(req)
		c.mu.RUnlock()
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("request after refresh failed: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update collections returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// CreateFolder creates a new folder with the given encrypted name.
func (c *VaultwardenClient) CreateFolder(encryptedName string) (*FolderResponse, error) {
	body := map[string]string{"name": encryptedName}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/folders", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	c.mu.RLock()
	c.setAuthHeader(req)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		if err := c.RefreshAuth(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(jsonBody))
		c.mu.RLock()
		c.setAuthHeader(req)
		c.mu.RUnlock()
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request after refresh failed: %w", err)
		}
		defer resp.Body.Close()
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("create folder returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var folder FolderResponse
	if err := json.Unmarshal(respBody, &folder); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &folder, nil
}

// ListFolders lists all folders.
func (c *VaultwardenClient) ListFolders() ([]FolderResponse, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/folders", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	c.mu.RLock()
	c.setAuthHeader(req)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		if err := c.RefreshAuth(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
		c.mu.RLock()
		c.setAuthHeader(req)
		c.mu.RUnlock()
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request after refresh failed: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list folders returned status %d: %s", resp.StatusCode, string(body))
	}

	var listResp foldersListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return listResp.Data, nil
}

// DeleteFolder deletes a folder by ID.
func (c *VaultwardenClient) DeleteFolder(id string) error {
	req, err := http.NewRequest("DELETE", c.baseURL+"/api/folders/"+id, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	c.mu.RLock()
	c.setAuthHeader(req)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		if err := c.RefreshAuth(); err != nil {
			return fmt.Errorf("token refresh failed: %w", err)
		}
		c.mu.RLock()
		c.setAuthHeader(req)
		c.mu.RUnlock()
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("request after refresh failed: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete folder returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// doJSON performs an authenticated JSON request and decodes the response.
func (c *VaultwardenClient) doJSON(method, path string, body interface{}) (*CipherResponse, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	c.mu.RLock()
	c.setAuthHeader(req)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		if err := c.RefreshAuth(); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}

		// Retry with new token.
		if body != nil {
			jsonBody, _ := json.Marshal(body)
			req.Body = io.NopCloser(bytes.NewReader(jsonBody))
		}
		c.mu.RLock()
		c.setAuthHeader(req)
		c.mu.RUnlock()

		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request after refresh failed: %w", err)
		}
		defer resp.Body.Close()
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var cipherResp CipherResponse
	if err := json.Unmarshal(respBody, &cipherResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &cipherResp, nil
}

// setAuthHeader sets the Authorization header on the request.
// Caller must hold at least a read lock on c.mu.
func (c *VaultwardenClient) setAuthHeader(req *http.Request) {
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
}
