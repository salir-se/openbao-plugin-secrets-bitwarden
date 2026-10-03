// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// testServer creates a mock Vaultwarden server for testing.
// It handles prelogin, token, sync, and cipher CRUD endpoints.
type testServer struct {
	server     *httptest.Server
	email      string
	password   string
	iterations int
	masterKey  []byte
	encKey     []byte
	macKey     []byte
	symEncKey  []byte
	symMacKey  []byte
	encSymKey  string // the encrypted user symmetric key
	orgID      string
	orgEncKey  []byte
	orgMacKey  []byte
	encOrgKey  string // org key encrypted with user's sym key
	ciphers    map[string]CipherResponse
	cipherMu   sync.Mutex
	nextID     int
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	ts := &testServer{
		email:      "test@example.com",
		password:   "testpassword",
		iterations: 1000, // low for test speed
		orgID:      "org-test-123",
		ciphers:    make(map[string]CipherResponse),
	}

	// Derive keys.
	var err error
	ts.masterKey, ts.encKey, ts.macKey, err = DeriveKeys(ts.email, ts.password, ts.iterations)
	if err != nil {
		t.Fatalf("deriving keys: %v", err)
	}

	// Create a synthetic user symmetric key (64 bytes).
	ts.symEncKey = make([]byte, 32)
	ts.symMacKey = make([]byte, 32)
	rand.Read(ts.symEncKey)
	rand.Read(ts.symMacKey)

	// Encrypt the symmetric key with the derived encKey/macKey.
	symKeyBytes := append(ts.symEncKey, ts.symMacKey...)
	ts.encSymKey, err = EncryptCipherString(string(symKeyBytes), ts.encKey, ts.macKey)
	if err != nil {
		t.Fatalf("encrypting symmetric key: %v", err)
	}

	// Create org keys.
	ts.orgEncKey = make([]byte, 32)
	ts.orgMacKey = make([]byte, 32)
	rand.Read(ts.orgEncKey)
	rand.Read(ts.orgMacKey)

	// Encrypt org key with user's symmetric key.
	orgKeyBytes := append(ts.orgEncKey, ts.orgMacKey...)
	ts.encOrgKey, err = EncryptCipherString(string(orgKeyBytes), ts.symEncKey, ts.symMacKey)
	if err != nil {
		t.Fatalf("encrypting org key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/identity/accounts/prelogin", ts.handlePrelogin)
	mux.HandleFunc("/identity/connect/token", ts.handleToken)
	mux.HandleFunc("/api/sync", ts.handleSync)
	mux.HandleFunc("/api/ciphers/create", ts.handleCreateOrgCipher)
	mux.HandleFunc("/api/ciphers/", ts.handleCipher)
	mux.HandleFunc("/api/ciphers", ts.handleCiphers)

	ts.server = httptest.NewServer(mux)
	return ts
}

func (ts *testServer) close() {
	ts.server.Close()
}

func (ts *testServer) url() string {
	return ts.server.URL
}

func (ts *testServer) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	json.NewEncoder(w).Encode(preloginResponse{
		KDF:           0,
		KDFIterations: ts.iterations,
	})
}

func (ts *testServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "password":
		// Verify the password hash.
		passwordHash := ComputePasswordHash(ts.masterKey, ts.password)
		if r.FormValue("password") != passwordHash {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(loginResponse{
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Key:          ts.encSymKey,
		})

	case "refresh_token":
		if r.FormValue("refresh_token") != "test-refresh-token" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(loginResponse{
			AccessToken:  "test-access-token-refreshed",
			RefreshToken: "test-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})

	default:
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
	}
}

func (ts *testServer) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ts.cipherMu.Lock()
	ciphers := make([]CipherResponse, 0, len(ts.ciphers))
	for _, c := range ts.ciphers {
		ciphers = append(ciphers, c)
	}
	ts.cipherMu.Unlock()

	json.NewEncoder(w).Encode(syncResponse{
		Profile: syncProfile{
			ID:    "user-123",
			Email: ts.email,
			Organizations: []syncOrganization{
				{
					ID:   ts.orgID,
					Name: "Test Org",
					Key:  ts.encOrgKey,
				},
			},
		},
		Ciphers: ciphers,
	})
}

func (ts *testServer) handleCreateOrgCipher(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req orgCipherCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ts.cipherMu.Lock()
	ts.nextID++
	id := fmt.Sprintf("cipher-%d", ts.nextID)
	resp := CipherResponse{
		ID:             id,
		Type:           req.Cipher.Type,
		Name:           req.Cipher.Name,
		OrganizationID: req.Cipher.OrganizationID,
		CollectionIDs:  req.CollectionIDs,
		RevisionDate:   "2026-03-21T00:00:00Z",
	}
	ts.ciphers[id] = resp
	ts.cipherMu.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (ts *testServer) handleCiphers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CipherRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ts.cipherMu.Lock()
	ts.nextID++
	id := fmt.Sprintf("cipher-%d", ts.nextID)
	resp := CipherResponse{
		ID:             id,
		Type:           req.Type,
		Name:           req.Name,
		OrganizationID: req.OrganizationID,
		RevisionDate:   "2026-03-21T00:00:00Z",
	}
	ts.ciphers[id] = resp
	ts.cipherMu.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (ts *testServer) handleCipher(w http.ResponseWriter, r *http.Request) {
	// Extract cipher ID from path: /api/ciphers/{id} or /api/ciphers/{id}/admin
	path := strings.TrimPrefix(r.URL.Path, "/api/ciphers/")
	if path == "create" {
		ts.handleCreateOrgCipher(w, r)
		return
	}

	// Strip /admin suffix (used by org cipher endpoints).
	id := strings.TrimSuffix(path, "/admin")

	switch r.Method {
	case "GET":
		ts.cipherMu.Lock()
		cipher, ok := ts.ciphers[id]
		ts.cipherMu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(cipher)

	case "PUT":
		var req CipherRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ts.cipherMu.Lock()
		_, ok := ts.ciphers[id]
		if !ok {
			ts.cipherMu.Unlock()
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		resp := CipherResponse{
			ID:             id,
			Type:           req.Type,
			Name:           req.Name,
			OrganizationID: req.OrganizationID,
			RevisionDate:   "2026-03-21T01:00:00Z",
		}
		ts.ciphers[id] = resp
		ts.cipherMu.Unlock()
		json.NewEncoder(w).Encode(resp)

	case "DELETE":
		ts.cipherMu.Lock()
		delete(ts.ciphers, id)
		ts.cipherMu.Unlock()
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func TestNewClient(t *testing.T) {
	ts := newTestServer(t)
	defer ts.close()

	t.Run("successful login", func(t *testing.T) {
		client, err := NewClient(&VaultwardenConfig{
			URL:      ts.url(),
			Email:    ts.email,
			Password: ts.password,
		}, nil)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		if client.accessToken == "" {
			t.Error("access token is empty after login")
		}
		if client.symEncKey == nil || client.symMacKey == nil {
			t.Error("symmetric keys are nil after login")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		_, err := NewClient(&VaultwardenConfig{
			URL:      ts.url(),
			Email:    ts.email,
			Password: "wrongpassword",
		}, nil)
		if err == nil {
			t.Error("expected error for wrong password")
		}
	})

	t.Run("missing URL", func(t *testing.T) {
		_, err := NewClient(&VaultwardenConfig{
			Email:    ts.email,
			Password: ts.password,
		}, nil)
		if err == nil {
			t.Error("expected error for missing URL")
		}
	})

	t.Run("missing email", func(t *testing.T) {
		_, err := NewClient(&VaultwardenConfig{
			URL:      ts.url(),
			Password: ts.password,
		}, nil)
		if err == nil {
			t.Error("expected error for missing email")
		}
	})

	t.Run("missing password", func(t *testing.T) {
		_, err := NewClient(&VaultwardenConfig{
			URL:   ts.url(),
			Email: ts.email,
		}, nil)
		if err == nil {
			t.Error("expected error for missing password")
		}
	})
}

func TestClientCipherOperations(t *testing.T) {
	ts := newTestServer(t)
	defer ts.close()

	client, err := NewClient(&VaultwardenConfig{
		URL:      ts.url(),
		Email:    ts.email,
		Password: ts.password,
	}, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	encKey, macKey := client.GetEncryptionKeys()

	t.Run("create personal cipher", func(t *testing.T) {
		encName, _ := EncryptCipherString("Test Cipher", encKey, macKey)

		resp, err := client.CreateCipher(&CipherRequest{
			Type: 1,
			Name: encName,
		})
		if err != nil {
			t.Fatalf("CreateCipher failed: %v", err)
		}

		if resp.ID == "" {
			t.Error("cipher ID is empty")
		}
	})

	t.Run("create org cipher", func(t *testing.T) {
		encName, _ := EncryptCipherString("Org Cipher", encKey, macKey)

		resp, err := client.CreateOrgCipher(&CipherRequest{
			Type:           1,
			Name:           encName,
			OrganizationID: ts.orgID,
		}, []string{"collection-1"})
		if err != nil {
			t.Fatalf("CreateOrgCipher failed: %v", err)
		}

		if resp.ID == "" {
			t.Error("cipher ID is empty")
		}
		if resp.OrganizationID != ts.orgID {
			t.Errorf("org ID = %q, want %q", resp.OrganizationID, ts.orgID)
		}
	})

	t.Run("get cipher", func(t *testing.T) {
		encName, _ := EncryptCipherString("Get Test", encKey, macKey)
		created, err := client.CreateCipher(&CipherRequest{
			Type: 1,
			Name: encName,
		})
		if err != nil {
			t.Fatalf("CreateCipher failed: %v", err)
		}

		got, err := client.GetCipher(created.ID)
		if err != nil {
			t.Fatalf("GetCipher failed: %v", err)
		}

		if got.ID != created.ID {
			t.Errorf("cipher ID = %q, want %q", got.ID, created.ID)
		}
	})

	t.Run("update cipher", func(t *testing.T) {
		encName, _ := EncryptCipherString("Update Test", encKey, macKey)
		created, err := client.CreateCipher(&CipherRequest{
			Type: 1,
			Name: encName,
		})
		if err != nil {
			t.Fatalf("CreateCipher failed: %v", err)
		}

		encNewName, _ := EncryptCipherString("Updated Name", encKey, macKey)
		updated, err := client.UpdateCipher(created.ID, &CipherRequest{
			Type: 1,
			Name: encNewName,
		})
		if err != nil {
			t.Fatalf("UpdateCipher failed: %v", err)
		}

		if updated.Name != encNewName {
			t.Error("cipher name was not updated")
		}
	})

	t.Run("delete cipher", func(t *testing.T) {
		encName, _ := EncryptCipherString("Delete Test", encKey, macKey)
		created, err := client.CreateCipher(&CipherRequest{
			Type: 1,
			Name: encName,
		})
		if err != nil {
			t.Fatalf("CreateCipher failed: %v", err)
		}

		err = client.DeleteCipher(created.ID)
		if err != nil {
			t.Fatalf("DeleteCipher failed: %v", err)
		}

		// Verify it's gone.
		_, err = client.GetCipher(created.ID)
		if err == nil {
			t.Error("expected error getting deleted cipher")
		}
	})

	t.Run("list ciphers", func(t *testing.T) {
		ciphers, err := client.ListCiphers()
		if err != nil {
			t.Fatalf("ListCiphers failed: %v", err)
		}

		// We created some ciphers above (some deleted). Should have at least some.
		if len(ciphers) == 0 {
			t.Error("expected at least one cipher")
		}
	})

	t.Run("find cipher by name", func(t *testing.T) {
		encName, _ := EncryptCipherString("FindMe", encKey, macKey)
		created, err := client.CreateCipher(&CipherRequest{
			Type: 1,
			Name: encName,
		})
		if err != nil {
			t.Fatalf("CreateCipher failed: %v", err)
		}

		found, err := client.FindCipherByName("FindMe", "")
		if err != nil {
			t.Fatalf("FindCipherByName failed: %v", err)
		}

		if found == nil {
			t.Fatal("cipher not found")
		}
		if found.ID != created.ID {
			t.Errorf("found cipher ID = %q, want %q", found.ID, created.ID)
		}
	})

	t.Run("find cipher by name not found", func(t *testing.T) {
		found, err := client.FindCipherByName("NonExistent12345", "")
		if err != nil {
			t.Fatalf("FindCipherByName failed: %v", err)
		}
		if found != nil {
			t.Error("expected nil for non-existent cipher")
		}
	})

	t.Run("find all ciphers by name returns duplicates", func(t *testing.T) {
		encName, _ := EncryptCipherString("DupTest", encKey, macKey)

		// Create three ciphers with the same name.
		ids := make([]string, 3)
		for i := range ids {
			created, err := client.CreateCipher(&CipherRequest{
				Type: 1,
				Name: encName,
			})
			if err != nil {
				t.Fatalf("CreateCipher[%d] failed: %v", i, err)
			}
			ids[i] = created.ID
		}

		matches, err := client.FindAllCiphersByName("DupTest", "")
		if err != nil {
			t.Fatalf("FindAllCiphersByName failed: %v", err)
		}
		if len(matches) < 3 {
			t.Errorf("expected at least 3 matches, got %d", len(matches))
		}

		// Clean up.
		for _, id := range ids {
			client.DeleteCipher(id)
		}
	})
}

func TestClientOrgKeys(t *testing.T) {
	ts := newTestServer(t)
	defer ts.close()

	client, err := NewClient(&VaultwardenConfig{
		URL:            ts.url(),
		Email:          ts.email,
		Password:       ts.password,
		OrganizationID: ts.orgID,
	}, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	t.Run("get org encryption keys", func(t *testing.T) {
		orgEncKey, orgMacKey, err := client.GetOrgEncryptionKeys(ts.orgID)
		if err != nil {
			t.Fatalf("GetOrgEncryptionKeys failed: %v", err)
		}

		if len(orgEncKey) != 32 {
			t.Errorf("org enc key length = %d, want 32", len(orgEncKey))
		}
		if len(orgMacKey) != 32 {
			t.Errorf("org mac key length = %d, want 32", len(orgMacKey))
		}

		// Keys should match what the test server set up.
		if !bytesEqual(orgEncKey, ts.orgEncKey) {
			t.Error("org enc key does not match")
		}
		if !bytesEqual(orgMacKey, ts.orgMacKey) {
			t.Error("org mac key does not match")
		}
	})

	t.Run("non-existent org", func(t *testing.T) {
		_, _, err := client.GetOrgEncryptionKeys("non-existent-org")
		if err == nil {
			t.Error("expected error for non-existent org")
		}
	})
}

func TestClientRefreshAuth(t *testing.T) {
	ts := newTestServer(t)
	defer ts.close()

	client, err := NewClient(&VaultwardenConfig{
		URL:      ts.url(),
		Email:    ts.email,
		Password: ts.password,
	}, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	err = client.RefreshAuth()
	if err != nil {
		t.Fatalf("RefreshAuth failed: %v", err)
	}

	if client.accessToken != "test-access-token-refreshed" {
		t.Errorf("access token = %q, want 'test-access-token-refreshed'", client.accessToken)
	}
}
