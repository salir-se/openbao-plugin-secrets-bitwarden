// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

// Test doubles shared by the unit tests: an in-process Bitwarden-compatible
// API server, an in-process OpenBao KV endpoint, and a fault-injecting
// storage wrapper. Nothing here talks to a real network service.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// errInjected is the error returned by faultStorage hooks.
var errInjected = errors.New("injected storage failure")

// recordedRequest is one request seen by a fake server.
type recordedRequest struct {
	Method string
	Path   string
	Auth   string
	Body   []byte
}

// fakeBW is an in-memory Bitwarden-compatible server. It enforces bearer
// tokens (so token refresh can be exercised), stores what the client sends
// and can decrypt it again with the keys it handed out.
type fakeBW struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex

	email      string
	password   string
	iterations int
	kdfType    int

	masterKey []byte
	symKey    []byte // 64 bytes: enc || mac
	rsaKey    *rsa.PrivateKey

	encSymKey  string
	encPrivKey string

	orgID     string
	orgKey    []byte // 64 bytes: enc || mac
	encOrgKey string
	extraOrgs []syncOrganization

	accessToken   string
	refreshToken  string
	tokenSeq      int
	rejectRefresh bool
	rotateRefresh bool

	nextID            int
	revision          int
	order             []string
	ciphers           map[string]CipherResponse
	cipherBodies      map[string]CipherRequest
	cipherCollections map[string][]string
	folders           map[string]FolderResponse
	folderOrder       []string
	collections       []CollectionResponse

	requests []recordedRequest

	// intercept, when set, runs before normal routing (after the request has
	// been recorded). Returning true means the request was fully handled.
	intercept func(w http.ResponseWriter, r *http.Request) bool
}

func newFakeBW(t *testing.T) *fakeBW {
	t.Helper()

	f := &fakeBW{
		t:                 t,
		email:             "sync@example.com",
		password:          "correct horse battery staple",
		iterations:        100, // low for test speed
		orgID:             "org-1",
		accessToken:       "access-0",
		refreshToken:      "refresh-0",
		ciphers:           map[string]CipherResponse{},
		cipherBodies:      map[string]CipherRequest{},
		cipherCollections: map[string][]string{},
		folders:           map[string]FolderResponse{},
	}

	var err error
	var encKey, macKey []byte
	f.masterKey, encKey, macKey, err = DeriveKeys(f.email, f.password, f.iterations)
	if err != nil {
		t.Fatalf("deriving keys: %v", err)
	}

	f.symKey = randomBytes(t, 64)
	f.encSymKey = mustEncrypt(t, string(f.symKey), encKey, macKey)

	f.rsaKey = sharedRSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(f.rsaKey)
	if err != nil {
		t.Fatalf("marshaling RSA key: %v", err)
	}
	f.encPrivKey = mustEncrypt(t, string(der), f.symKey[:32], f.symKey[32:])

	f.orgKey = randomBytes(t, 64)
	f.encOrgKey = mustEncrypt(t, string(f.orgKey), f.symKey[:32], f.symKey[32:])

	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

var (
	rsaKeyOnce sync.Once
	rsaKeyVal  *rsa.PrivateKey
	rsaKeyErr  error
)

// sharedRSAKey returns one RSA-2048 key for the whole test binary; generating
// a key per fake server would dominate the test run time.
func sharedRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaKeyOnce.Do(func() {
		rsaKeyVal, rsaKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if rsaKeyErr != nil {
		t.Fatalf("generating RSA key: %v", rsaKeyErr)
	}
	return rsaKeyVal
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func mustEncrypt(t *testing.T, plaintext string, encKey, macKey []byte) string {
	t.Helper()
	cs, err := EncryptCipherString(plaintext, encKey, macKey)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	return cs
}

// rsaWrap encrypts data to the fake account's RSA public key as a type-4
// CipherString, the way Bitwarden shares an organization key with a member.
func (f *fakeBW) rsaWrap(data []byte) string {
	f.t.Helper()
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &f.rsaKey.PublicKey, data, nil)
	if err != nil {
		f.t.Fatalf("RSA encrypt: %v", err)
	}
	return "4." + base64.StdEncoding.EncodeToString(ct)
}

func (f *fakeBW) url() string { return f.srv.URL }

// client logs a fresh client in against the fake.
func (f *fakeBW) client() *VaultwardenClient {
	f.t.Helper()
	c, err := NewClient(&VaultwardenConfig{URL: f.url(), Email: f.email, Password: f.password}, nil)
	if err != nil {
		f.t.Fatalf("NewClient: %v", err)
	}
	return c
}

// expireToken invalidates the access token the client currently holds. A
// refresh hands out the new one.
func (f *fakeBW) expireToken() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenSeq++
	f.accessToken = fmt.Sprintf("access-%d", f.tokenSeq)
}

func (f *fakeBW) setIntercept(fn func(w http.ResponseWriter, r *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.intercept = fn
}

// seen returns the recorded requests matching method and path.
func (f *fakeBW) seen(method, path string) []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recordedRequest
	for _, r := range f.requests {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// dec decrypts a CipherString with the user key (org=false) or the
// organization key (org=true), failing the test if it cannot.
func (f *fakeBW) dec(cs string, org bool) string {
	f.t.Helper()
	key := f.symKey
	if org {
		key = f.orgKey
	}
	out, err := DecryptCipherString(cs, key[:32], key[32:])
	if err != nil {
		f.t.Fatalf("decrypting %q: %v", cs, err)
	}
	return out
}

// seedCipher stores a cipher directly on the fake and returns its ID.
func (f *fakeBW) seedCipher(name string, org bool, revisionDate string) string {
	f.t.Helper()
	key := f.symKey
	orgID := ""
	if org {
		key = f.orgKey
		orgID = f.orgID
	}
	enc := mustEncrypt(f.t, name, key[:32], key[32:])

	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := fmt.Sprintf("cipher-%d", f.nextID)
	f.ciphers[id] = CipherResponse{ID: id, Type: cipherTypeLogin, Name: enc, OrganizationID: orgID, RevisionDate: revisionDate}
	f.order = append(f.order, id)
	return id
}

func (f *fakeBW) cipherIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.order...)
}

func (f *fakeBW) body(id string) CipherRequest {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.cipherBodies[id]
	if !ok {
		f.t.Fatalf("no stored request body for cipher %q", id)
	}
	return b
}

func (f *fakeBW) nextRevision() string {
	f.revision++
	return fmt.Sprintf("2026-01-01T00:00:%02dZ", f.revision)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// killConn drops the TCP connection without writing a response, which the
// HTTP client reports as a transport error.
func killConn(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		conn.Close()
	}
}

// truncatedBody promises more bytes than it sends and then drops the
// connection, so reading the response body fails part-way.
func truncatedBody(w http.ResponseWriter) {
	w.Header().Set("Content-Length", "1000")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"id":`))
	w.(http.Flusher).Flush()
	killConn(w)
}

func (f *fakeBW) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))

	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{
		Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: body,
	})
	intercept := f.intercept
	f.mu.Unlock()

	if intercept != nil && intercept(w, r) {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	path := r.URL.Path
	switch path {
	case "/alive":
		writeJSON(w, http.StatusOK, "ok")
		return
	case "/identity/accounts/prelogin":
		writeJSON(w, http.StatusOK, preloginResponse{KDF: f.kdfType, KDFIterations: f.iterations})
		return
	case "/identity/connect/token":
		f.handleToken(w, r)
		return
	}

	if r.Header.Get("Authorization") != "Bearer "+f.accessToken {
		http.Error(w, `{"message":"invalid token"}`, http.StatusUnauthorized)
		return
	}

	switch {
	case path == "/api/sync" && r.Method == http.MethodGet:
		orgs := append([]syncOrganization{{ID: f.orgID, Name: "Test Org", Key: f.encOrgKey}}, f.extraOrgs...)
		ciphers := make([]CipherResponse, 0, len(f.order))
		for _, id := range f.order {
			ciphers = append(ciphers, f.ciphers[id])
		}
		writeJSON(w, http.StatusOK, syncResponse{
			Profile: syncProfile{ID: "user-1", Email: f.email, Organizations: orgs},
			Ciphers: ciphers,
		})

	case path == "/api/ciphers" && r.Method == http.MethodPost:
		var req CipherRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, f.storeCipher("", req, nil))

	case path == "/api/ciphers/create" && r.Method == http.MethodPost:
		var req orgCipherCreateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, f.storeCipher("", req.Cipher, req.CollectionIDs))

	case strings.HasPrefix(path, "/api/ciphers/"):
		f.handleCipher(w, r, body, strings.TrimPrefix(path, "/api/ciphers/"))

	case strings.HasPrefix(path, "/api/organizations/") && strings.HasSuffix(path, "/collections") && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, collectionsListResponse{Data: f.collections})

	case path == "/api/folders" && r.Method == http.MethodGet:
		list := make([]FolderResponse, 0, len(f.folderOrder))
		for _, id := range f.folderOrder {
			list = append(list, f.folders[id])
		}
		writeJSON(w, http.StatusOK, foldersListResponse{Data: list})

	case path == "/api/folders" && r.Method == http.MethodPost:
		var req map[string]string
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.nextID++
		id := fmt.Sprintf("folder-%d", f.nextID)
		folder := FolderResponse{ID: id, Name: req["name"], RevisionDate: f.nextRevision()}
		f.folders[id] = folder
		f.folderOrder = append(f.folderOrder, id)
		writeJSON(w, http.StatusOK, folder)

	case strings.HasPrefix(path, "/api/folders/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/api/folders/")
		if _, ok := f.folders[id]; !ok {
			http.Error(w, `{"message":"folder not found"}`, http.StatusNotFound)
			return
		}
		delete(f.folders, id)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "not found: "+r.Method+" "+path, http.StatusNotFound)
	}
}

func (f *fakeBW) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	switch r.FormValue("grant_type") {
	case "password":
		if r.FormValue("username") != f.email || r.FormValue("password") != ComputePasswordHash(f.masterKey, f.password) {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, loginResponse{
			AccessToken:  f.accessToken,
			RefreshToken: f.refreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Key:          f.encSymKey,
			PrivateKey:   f.encPrivKey,
		})
	case "refresh_token":
		if f.rejectRefresh || r.FormValue("refresh_token") != f.refreshToken {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		resp := loginResponse{AccessToken: f.accessToken, TokenType: "Bearer", ExpiresIn: 3600}
		if f.rotateRefresh {
			f.refreshToken += "+"
			resp.RefreshToken = f.refreshToken
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
	}
}

// storeCipher creates (id == "") or replaces a cipher. Caller holds f.mu.
func (f *fakeBW) storeCipher(id string, req CipherRequest, collectionIDs []string) CipherResponse {
	if id == "" {
		f.nextID++
		id = fmt.Sprintf("cipher-%d", f.nextID)
		f.order = append(f.order, id)
	}
	if collectionIDs != nil {
		f.cipherCollections[id] = collectionIDs
	}
	resp := CipherResponse{
		ID:             id,
		Type:           req.Type,
		Name:           req.Name,
		Notes:          req.Notes,
		OrganizationID: req.OrganizationID,
		CollectionIDs:  f.cipherCollections[id],
		RevisionDate:   f.nextRevision(),
		Login:          req.Login,
		Fields:         req.Fields,
	}
	f.ciphers[id] = resp
	f.cipherBodies[id] = req
	return resp
}

// handleCipher serves /api/ciphers/{id}[/admin] and
// /api/ciphers/{id}/collections[/admin]. Caller holds f.mu.
func (f *fakeBW) handleCipher(w http.ResponseWriter, r *http.Request, body []byte, rest string) {
	rest = strings.TrimSuffix(rest, "/admin")
	collections := strings.HasSuffix(rest, "/collections")
	id := strings.TrimSuffix(rest, "/collections")

	if _, ok := f.ciphers[id]; !ok {
		http.Error(w, `{"message":"cipher not found"}`, http.StatusNotFound)
		return
	}

	switch {
	case collections && r.Method == http.MethodPut:
		var req cipherCollectionsRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.cipherCollections[id] = req.CollectionIDs
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, f.ciphers[id])
	case r.Method == http.MethodPut:
		var req CipherRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, f.storeCipher(id, req, nil))
	case r.Method == http.MethodDelete:
		delete(f.ciphers, id)
		delete(f.cipherBodies, id)
		for i, v := range f.order {
			if v == id {
				f.order = append(f.order[:i], f.order[i+1:]...)
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// fakeBao is an in-process stand-in for OpenBao's KV HTTP API.
type fakeBao struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	token    string                            // required X-Vault-Token
	v2       map[string]map[string]interface{} // path -> KV v2 payload
	v1       map[string]map[string]interface{} // path -> KV v1 payload
	tokens   []string                          // tokens presented, in order
	requests int
}

func newFakeBao(t *testing.T, useTLS bool) *fakeBao {
	t.Helper()
	f := &fakeBao{
		t:     t,
		token: "kv-reader-token",
		v2:    map[string]map[string]interface{}{},
		v1:    map[string]map[string]interface{}{},
	}
	handler := http.HandlerFunc(f.serve)
	if useTLS {
		f.srv = httptest.NewTLSServer(handler)
	} else {
		f.srv = httptest.NewServer(handler)
	}
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeBao) url() string { return f.srv.URL }

func (f *fakeBao) put(path string, data map[string]interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.v2[path] = data
}

func (f *fakeBao) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func (f *fakeBao) seenTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tokens...)
}

func (f *fakeBao) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests++
	token := r.Header.Get("X-Vault-Token")
	f.tokens = append(f.tokens, token)

	if token != f.token {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"errors": []string{"permission denied"}})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	if data, ok := f.v2[path]; ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"data": map[string]interface{}{"data": data, "metadata": map[string]interface{}{"version": 1}},
		})
		return
	}
	if data, ok := f.v1[path]; ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{"data": data})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]interface{}{"errors": []string{}})
}

// faultStorage wraps a logical.Storage and lets a test make individual
// operations fail. Each hook receives the key and returns the error to
// inject, or nil to pass the call through.
type faultStorage struct {
	logical.Storage
	onGet    func(key string) error
	onPut    func(key string) error
	onList   func(prefix string) error
	onDelete func(key string) error
}

func (s *faultStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if s.onGet != nil {
		if err := s.onGet(key); err != nil {
			return nil, err
		}
	}
	return s.Storage.Get(ctx, key)
}

func (s *faultStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if s.onPut != nil {
		if err := s.onPut(entry.Key); err != nil {
			return err
		}
	}
	return s.Storage.Put(ctx, entry)
}

func (s *faultStorage) List(ctx context.Context, prefix string) ([]string, error) {
	if s.onList != nil {
		if err := s.onList(prefix); err != nil {
			return nil, err
		}
	}
	return s.Storage.List(ctx, prefix)
}

func (s *faultStorage) Delete(ctx context.Context, key string) error {
	if s.onDelete != nil {
		if err := s.onDelete(key); err != nil {
			return err
		}
	}
	return s.Storage.Delete(ctx, key)
}

// failOn returns a hook that injects errInjected for exactly the given key.
func failOn(key string) func(string) error {
	return func(k string) error {
		if k == key {
			return errInjected
		}
		return nil
	}
}

// syncEnv wires a backend to a fake Bitwarden server and a fake OpenBao KV.
type syncEnv struct {
	t       *testing.T
	ctx     context.Context
	b       *vaultwardenBackend
	storage logical.Storage
	bw      *fakeBW
	bao     *fakeBao
	org     bool
}

// newSyncEnv builds a configured backend. With org=true the plugin is
// configured with the fake's organization, otherwise it syncs to the
// personal vault.
func newSyncEnv(t *testing.T, org bool) *syncEnv {
	t.Helper()

	b, storage := getTestBackend(t)
	e := &syncEnv{
		t:       t,
		ctx:     context.Background(),
		b:       b,
		storage: storage,
		bw:      newFakeBW(t),
		bao:     newFakeBao(t, false),
		org:     org,
	}

	cfg := map[string]interface{}{
		"url":       e.bw.url(),
		"email":     e.bw.email,
		"password":  e.bw.password,
		"bao_addr":  e.bao.url(),
		"bao_token": e.bao.token,
	}
	if org {
		cfg["organization_id"] = e.bw.orgID
	}
	e.mustOK(e.do(logical.UpdateOperation, "config", cfg))
	return e
}

// do sends a request through the backend's router, like OpenBao would.
func (e *syncEnv) do(op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	e.t.Helper()
	return e.b.HandleRequest(e.ctx, &logical.Request{
		Operation: op,
		Path:      path,
		Storage:   e.storage,
		Data:      data,
	})
}

// mustOK fails the test if a request returned an error or error response.
func (e *syncEnv) mustOK(resp *logical.Response, err error) *logical.Response {
	e.t.Helper()
	if err != nil {
		e.t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		e.t.Fatalf("unexpected error response: %v", resp.Error())
	}
	return resp
}

// loginRole creates a login-type role named name reading secret/data/<name>.
func (e *syncEnv) loginRole(name string, extra map[string]interface{}) {
	e.t.Helper()
	data := map[string]interface{}{
		"source_path": "secret/data/" + name,
		"cipher_name": "Cipher " + name,
		"user_field":  "username",
		"pass_field":  "password",
		"url_field":   "url",
	}
	for k, v := range extra {
		data[k] = v
	}
	e.mustOK(e.do(logical.UpdateOperation, "roles/"+name, data))
}

func (e *syncEnv) role(name string) *roleEntry {
	e.t.Helper()
	role, err := e.b.readRole(e.ctx, e.storage, name)
	if err != nil {
		e.t.Fatalf("reading role %q: %v", name, err)
	}
	if role == nil {
		e.t.Fatalf("role %q does not exist", name)
	}
	return role
}

// putRaw stores raw bytes under a storage key (used to plant corrupt entries).
func putRaw(t *testing.T, s logical.Storage, key, value string) {
	t.Helper()
	if err := s.Put(context.Background(), &logical.StorageEntry{Key: key, Value: []byte(value)}); err != nil {
		t.Fatalf("planting %q: %v", key, err)
	}
}

// wantErr asserts err is non-nil and mentions substr.
func wantErr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), substr)
	}
}

// wantErrResp asserts resp is an error response mentioning substr.
func wantErrResp(t *testing.T, resp *logical.Response, err error, substr string) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response containing %q, got %+v", substr, resp)
	}
	if !strings.Contains(resp.Error().Error(), substr) {
		t.Fatalf("error response = %q, want it to contain %q", resp.Error().Error(), substr)
	}
}

// reconfigure replaces the stored plugin config. Keys in overrides replace
// the defaults; a nil value removes the key.
func (e *syncEnv) reconfigure(overrides map[string]interface{}) {
	e.t.Helper()
	cfg := map[string]interface{}{
		"url":       e.bw.url(),
		"email":     e.bw.email,
		"password":  e.bw.password,
		"bao_addr":  e.bao.url(),
		"bao_token": e.bao.token,
	}
	if e.org {
		cfg["organization_id"] = e.bw.orgID
	}
	for k, v := range overrides {
		if v == nil {
			delete(cfg, k)
		} else {
			cfg[k] = v
		}
	}
	e.mustOK(e.do(logical.DeleteOperation, "config", nil))
	e.mustOK(e.do(logical.UpdateOperation, "config", cfg))
}

// cachedClient returns the backend's cached API client (nil when reset).
func (e *syncEnv) cachedClient() *VaultwardenClient {
	e.b.mu.RLock()
	defer e.b.mu.RUnlock()
	return e.b.client
}

// writes counts cipher create/update requests the fake server has seen.
func (f *fakeBW) writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r.Path, "/api/ciphers") && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
			n++
		}
	}
	return n
}
