// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
)

// bareClient returns a client that has not logged in.
func bareClient(baseURL string) *VaultwardenClient {
	return &VaultwardenClient{
		baseURL:    baseURL,
		orgKeys:    make(map[string]orgKeyPair),
		httpClient: &http.Client{Timeout: 5 * time.Second},
		logger:     hclog.NewNullLogger(),
	}
}

// invalidBaseURL makes http.NewRequest fail (control character in host).
const invalidBaseURL = "http://bad\x7fhost"

// on builds an intercept that applies fn to requests for method+path only.
func on(method, path string, fn func(w http.ResponseWriter, n int)) func(http.ResponseWriter, *http.Request) bool {
	var mu sync.Mutex
	n := 0
	return func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != method || r.URL.Path != path {
			return false
		}
		mu.Lock()
		n++
		cur := n
		mu.Unlock()
		fn(w, cur)
		return true
	}
}

func TestPreloginErrors(t *testing.T) {
	t.Run("connection failure", func(t *testing.T) {
		f := newFakeBW(t)
		c := bareClient(f.url())
		f.srv.Close()
		_, _, err := c.Prelogin(f.email)
		wantErr(t, err, "prelogin request failed")
	})

	t.Run("non-200 status", func(t *testing.T) {
		f := newFakeBW(t)
		f.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		})
		_, _, err := bareClient(f.url()).Prelogin(f.email)
		wantErr(t, err, "prelogin returned status 503")
	})

	t.Run("malformed response", func(t *testing.T) {
		f := newFakeBW(t)
		f.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
			_, _ = w.Write([]byte("<html>not json"))
			return true
		})
		_, _, err := bareClient(f.url()).Prelogin(f.email)
		wantErr(t, err, "decoding prelogin response")
	})

	t.Run("returns server KDF parameters", func(t *testing.T) {
		f := newFakeBW(t)
		f.kdfType, f.iterations = 1, 4242
		kdf, iter, err := bareClient(f.url()).Prelogin(f.email)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if kdf != 1 || iter != 4242 {
			t.Errorf("got kdf=%d iterations=%d, want 1/4242", kdf, iter)
		}
	})
}

func TestLoginErrors(t *testing.T) {
	t.Run("prelogin failure is reported", func(t *testing.T) {
		f := newFakeBW(t)
		c := bareClient(f.url())
		f.srv.Close()
		wantErr(t, c.Login(f.email, f.password), "prelogin:")
	})

	t.Run("argon2 KDF is rejected", func(t *testing.T) {
		f := newFakeBW(t)
		f.kdfType = 1
		err := bareClient(f.url()).Login(f.email, f.password)
		wantErr(t, err, "unsupported KDF type: 1")
		if got := f.seen("POST", "/identity/connect/token"); len(got) != 0 {
			t.Errorf("must not attempt a token request with an unsupported KDF, saw %d", len(got))
		}
	})

	t.Run("empty master password", func(t *testing.T) {
		f := newFakeBW(t)
		wantErr(t, bareClient(f.url()).Login(f.email, ""), "deriving keys")
	})

	t.Run("token endpoint unreachable", func(t *testing.T) {
		f := newFakeBW(t)
		f.setIntercept(on("POST", "/identity/connect/token", func(w http.ResponseWriter, _ int) { killConn(w) }))
		wantErr(t, bareClient(f.url()).Login(f.email, f.password), "login request failed")
	})

	t.Run("wrong password includes server body", func(t *testing.T) {
		f := newFakeBW(t)
		c := bareClient(f.url())
		err := c.Login(f.email, "not the password")
		wantErr(t, err, "login returned status 400")
		wantErr(t, err, "invalid_grant")
		if c.accessToken != "" {
			t.Errorf("access token must stay empty after a failed login")
		}
	})

	t.Run("malformed token response", func(t *testing.T) {
		f := newFakeBW(t)
		f.setIntercept(on("POST", "/identity/connect/token", func(w http.ResponseWriter, _ int) {
			_, _ = w.Write([]byte("{broken"))
		}))
		wantErr(t, bareClient(f.url()).Login(f.email, f.password), "decoding login response")
	})

	t.Run("undecryptable account key", func(t *testing.T) {
		f := newFakeBW(t)
		// Account key wrapped with keys the client cannot derive.
		f.encSymKey = mustEncrypt(t, string(randomBytes(t, 64)), randomBytes(t, 32), randomBytes(t, 32))
		c := bareClient(f.url())
		wantErr(t, c.Login(f.email, f.password), "decrypting symmetric key")
		if enc, mac := c.GetEncryptionKeys(); enc != nil || mac != nil {
			t.Errorf("encryption keys must not be set after a failed login")
		}
	})
}

func TestLoginPrivateKeyHandling(t *testing.T) {
	t.Run("private key is decrypted", func(t *testing.T) {
		f := newFakeBW(t)
		c := f.client()
		if c.privateKey == nil {
			t.Fatal("expected RSA private key to be available after login")
		}
		if !c.privateKey.PublicKey.Equal(&f.rsaKey.PublicKey) {
			t.Error("decrypted private key does not match the account key")
		}
		enc, mac := c.GetEncryptionKeys()
		if !bytes.Equal(enc, f.symKey[:32]) || !bytes.Equal(mac, f.symKey[32:]) {
			t.Error("client symmetric keys do not match the account key")
		}
	})

	t.Run("corrupt private key does not fail login", func(t *testing.T) {
		f := newFakeBW(t)
		f.encPrivKey = mustEncrypt(t, "this is not PKCS8", f.symKey[:32], f.symKey[32:])
		c := f.client()
		if c.privateKey != nil {
			t.Error("private key must be nil when it cannot be parsed")
		}
	})

	t.Run("absent private key", func(t *testing.T) {
		f := newFakeBW(t)
		f.encPrivKey = ""
		if c := f.client(); c.privateKey != nil {
			t.Error("private key must be nil when the server sends none")
		}
	})
}

func TestNewClientLoginFailure(t *testing.T) {
	f := newFakeBW(t)
	_, err := NewClient(&VaultwardenConfig{URL: f.url() + "/", Email: f.email, Password: "wrong"}, nil)
	wantErr(t, err, "login failed")
}

func TestRefreshAuth(t *testing.T) {
	t.Run("no refresh token", func(t *testing.T) {
		f := newFakeBW(t)
		wantErr(t, bareClient(f.url()).RefreshAuth(), "no refresh token available")
		if got := f.seen("POST", "/identity/connect/token"); len(got) != 0 {
			t.Errorf("no request expected without a refresh token, saw %d", len(got))
		}
	})

	t.Run("connection failure", func(t *testing.T) {
		f := newFakeBW(t)
		c := f.client()
		f.srv.Close()
		wantErr(t, c.RefreshAuth(), "refresh request failed")
	})

	t.Run("rejected refresh keeps old token", func(t *testing.T) {
		f := newFakeBW(t)
		c := f.client()
		f.rejectRefresh = true
		err := c.RefreshAuth()
		wantErr(t, err, "refresh returned status 400")
		wantErr(t, err, "invalid_grant")
		if c.accessToken != "access-0" {
			t.Errorf("access token changed to %q after failed refresh", c.accessToken)
		}
	})

	t.Run("malformed response", func(t *testing.T) {
		f := newFakeBW(t)
		c := f.client()
		f.setIntercept(on("POST", "/identity/connect/token", func(w http.ResponseWriter, _ int) {
			_, _ = w.Write([]byte("nope"))
		}))
		wantErr(t, c.RefreshAuth(), "decoding refresh response")
	})

	t.Run("new access token, refresh token kept when not rotated", func(t *testing.T) {
		f := newFakeBW(t)
		c := f.client()
		f.expireToken()
		if err := c.RefreshAuth(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.accessToken != "access-1" {
			t.Errorf("access token = %q, want access-1", c.accessToken)
		}
		if c.refreshToken != "refresh-0" {
			t.Errorf("refresh token = %q, want it unchanged", c.refreshToken)
		}
	})

	t.Run("rotated refresh token is adopted", func(t *testing.T) {
		f := newFakeBW(t)
		c := f.client()
		f.rotateRefresh = true
		if err := c.RefreshAuth(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.refreshToken != "refresh-0+" {
			t.Errorf("refresh token = %q, want refresh-0+", c.refreshToken)
		}
		// The rotated token must be the one used next time.
		if err := c.RefreshAuth(); err != nil {
			t.Fatalf("second refresh with rotated token failed: %v", err)
		}
	})
}

func TestClientEncryptUsesAccountKey(t *testing.T) {
	f := newFakeBW(t)
	cs, err := f.client().Encrypt("hello")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got := f.dec(cs, false); got != "hello" {
		t.Errorf("round trip = %q, want hello", got)
	}

	if _, err := bareClient(f.url()).Encrypt("x"); err == nil {
		t.Error("Encrypt must fail when the client has no keys")
	}
}

func TestOrgKeyHandling(t *testing.T) {
	f := newFakeBW(t)
	rsaOrgKey := randomBytes(t, 64)
	garbage := "4." + base64.StdEncoding.EncodeToString(randomBytes(t, 256))
	f.extraOrgs = []syncOrganization{
		{ID: "org-empty", Key: ""},
		{ID: "org-rsa", Key: f.rsaWrap(rsaOrgKey)},
		{ID: "org-rsa-bad", Key: garbage},
		{ID: "org-aes-bad", Key: mustEncrypt(t, string(randomBytes(t, 64)), randomBytes(t, 32), randomBytes(t, 32))},
		{ID: "org-short", Key: mustEncrypt(t, string(randomBytes(t, 32)), f.symKey[:32], f.symKey[32:])},
	}
	c := f.client()

	t.Run("AES-wrapped org key", func(t *testing.T) {
		enc, mac, err := c.GetOrgEncryptionKeys(f.orgID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(enc, f.orgKey[:32]) || !bytes.Equal(mac, f.orgKey[32:]) {
			t.Error("org keys do not match")
		}
	})

	t.Run("RSA-wrapped org key", func(t *testing.T) {
		enc, mac, err := c.GetOrgEncryptionKeys("org-rsa")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(enc, rsaOrgKey[:32]) || !bytes.Equal(mac, rsaOrgKey[32:]) {
			t.Error("RSA-wrapped org keys do not match")
		}
	})

	t.Run("cached keys do not trigger another sync", func(t *testing.T) {
		before := len(f.seen("GET", "/api/sync"))
		if _, _, err := c.GetOrgEncryptionKeys("org-rsa"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if after := len(f.seen("GET", "/api/sync")); after != before {
			t.Errorf("sync requests went from %d to %d for a cached key", before, after)
		}
	})

	for _, id := range []string{"org-empty", "org-rsa-bad", "org-aes-bad", "org-short", "org-unknown"} {
		t.Run("unusable key for "+id, func(t *testing.T) {
			_, _, err := c.GetOrgEncryptionKeys(id)
			wantErr(t, err, fmt.Sprintf("organization %s not found or no key available", id))
		})
	}

	t.Run("RSA-wrapped key without a private key", func(t *testing.T) {
		f2 := newFakeBW(t)
		f2.encPrivKey = ""
		f2.extraOrgs = []syncOrganization{{ID: "org-rsa", Key: f2.rsaWrap(rsaOrgKey)}}
		_, _, err := f2.client().GetOrgEncryptionKeys("org-rsa")
		wantErr(t, err, "not found or no key available")
	})

	t.Run("sync failure", func(t *testing.T) {
		f2 := newFakeBW(t)
		c2 := f2.client()
		f2.setIntercept(on("GET", "/api/sync", func(w http.ResponseWriter, _ int) {
			http.Error(w, "sync broke", http.StatusInternalServerError)
		}))
		_, _, err := c2.GetOrgEncryptionKeys(f2.orgID)
		wantErr(t, err, "fetching org keys")
		wantErr(t, err, "sync broke")
	})
}

func TestFindCiphersByName(t *testing.T) {
	f := newFakeBW(t)
	personal := f.seedCipher("Shared Name", false, "2026-01-01T00:00:00Z")
	orgOld := f.seedCipher("Shared Name", true, "2026-01-02T00:00:00Z")
	orgNew := f.seedCipher("Shared Name", true, "2026-01-03T00:00:00Z")
	f.seedCipher("Other", true, "2026-01-04T00:00:00Z")

	// An org cipher whose name was encrypted with a key we do not hold.
	f.mu.Lock()
	f.ciphers["foreign"] = CipherResponse{
		ID: "foreign", OrganizationID: f.orgID,
		Name: mustEncrypt(t, "Shared Name", randomBytes(t, 32), randomBytes(t, 32)),
	}
	f.order = append([]string{"foreign"}, f.order...)
	f.mu.Unlock()

	c := f.client()

	t.Run("org lookup returns first org match", func(t *testing.T) {
		got, err := c.FindCipherByName("Shared Name", f.orgID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != orgOld {
			t.Fatalf("got %+v, want cipher %s", got, orgOld)
		}
	})

	t.Run("personal lookup skips ciphers it cannot decrypt", func(t *testing.T) {
		got, err := c.FindCipherByName("Shared Name", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != personal {
			t.Fatalf("got %+v, want personal cipher %s", got, personal)
		}
	})

	t.Run("not found is nil without error", func(t *testing.T) {
		got, err := c.FindCipherByName("Missing", f.orgID)
		if err != nil || got != nil {
			t.Fatalf("got (%+v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("find all returns every org match only", func(t *testing.T) {
		got, err := c.FindAllCiphersByName("Shared Name", f.orgID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 || got[0].ID != orgOld || got[1].ID != orgNew {
			t.Fatalf("got %d matches %+v, want [%s %s]", len(got), got, orgOld, orgNew)
		}
	})

	t.Run("find all in personal vault", func(t *testing.T) {
		got, err := c.FindAllCiphersByName("Shared Name", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].ID != personal {
			t.Fatalf("got %+v, want only %s", got, personal)
		}
	})

	t.Run("find all with no match is empty", func(t *testing.T) {
		got, err := c.FindAllCiphersByName("Missing", f.orgID)
		if err != nil || len(got) != 0 {
			t.Fatalf("got (%+v, %v), want empty", got, err)
		}
	})

	t.Run("unknown organization", func(t *testing.T) {
		_, err := c.FindCipherByName("Shared Name", "org-unknown")
		wantErr(t, err, "getting org encryption keys")
		_, err = c.FindAllCiphersByName("Shared Name", "org-unknown")
		wantErr(t, err, "getting org encryption keys")
	})

	t.Run("listing failure", func(t *testing.T) {
		f.setIntercept(on("GET", "/api/sync", func(w http.ResponseWriter, _ int) {
			http.Error(w, "no", http.StatusBadGateway)
		}))
		defer f.setIntercept(nil)
		_, err := c.FindCipherByName("Shared Name", f.orgID)
		wantErr(t, err, "listing ciphers")
		_, err = c.FindAllCiphersByName("Shared Name", f.orgID)
		wantErr(t, err, "listing ciphers")
	})
}

// clientOp describes one authenticated API call for the shared failure matrix.
type clientOp struct {
	name      string
	method    string
	path      string
	hasBody   bool // request carries a JSON body that must survive a retry
	decodes   bool // response body is parsed as JSON
	readsBody bool // response body is read fully before the status check
	call      func(c *VaultwardenClient) error
}

const (
	opCipherID = "cipher-1"
	opFolderID = "folder-op"
)

func clientOps() []clientOp {
	req := &CipherRequest{Type: cipherTypeLogin, Name: "2.x|y|z"}
	return []clientOp{
		{name: "ListCiphers", method: "GET", path: "/api/sync", decodes: true,
			call: func(c *VaultwardenClient) error { _, err := c.ListCiphers(); return err }},
		{name: "GetCipher", method: "GET", path: "/api/ciphers/" + opCipherID, decodes: true,
			call: func(c *VaultwardenClient) error { _, err := c.GetCipher(opCipherID); return err }},
		{name: "DeleteCipher", method: "DELETE", path: "/api/ciphers/" + opCipherID,
			call: func(c *VaultwardenClient) error { return c.DeleteCipher(opCipherID) }},
		{name: "DeleteOrgCipher", method: "DELETE", path: "/api/ciphers/" + opCipherID + "/admin",
			call: func(c *VaultwardenClient) error { return c.DeleteOrgCipher(opCipherID) }},
		{name: "CreateCipher", method: "POST", path: "/api/ciphers", hasBody: true, decodes: true, readsBody: true,
			call: func(c *VaultwardenClient) error { _, err := c.CreateCipher(req); return err }},
		{name: "CreateOrgCipher", method: "POST", path: "/api/ciphers/create", hasBody: true, decodes: true, readsBody: true,
			call: func(c *VaultwardenClient) error { _, err := c.CreateOrgCipher(req, []string{"col-1"}); return err }},
		{name: "UpdateCipher", method: "PUT", path: "/api/ciphers/" + opCipherID, hasBody: true, decodes: true, readsBody: true,
			call: func(c *VaultwardenClient) error { _, err := c.UpdateCipher(opCipherID, req); return err }},
		{name: "UpdateOrgCipher", method: "PUT", path: "/api/ciphers/" + opCipherID + "/admin", hasBody: true, decodes: true, readsBody: true,
			call: func(c *VaultwardenClient) error { _, err := c.UpdateOrgCipher(opCipherID, req); return err }},
		{name: "ListOrgCollections", method: "GET", path: "/api/organizations/org-1/collections", decodes: true,
			call: func(c *VaultwardenClient) error { _, err := c.ListOrgCollections("org-1"); return err }},
		{name: "UpdateCipherCollections", method: "PUT", path: "/api/ciphers/" + opCipherID + "/collections", hasBody: true,
			call: func(c *VaultwardenClient) error {
				return c.UpdateCipherCollections(opCipherID, []string{"col-1", "col-2"}, false)
			}},
		{name: "UpdateCipherCollectionsAdmin", method: "PUT", path: "/api/ciphers/" + opCipherID + "/collections/admin", hasBody: true,
			call: func(c *VaultwardenClient) error {
				return c.UpdateCipherCollections(opCipherID, []string{"col-1", "col-2"}, true)
			}},
		{name: "CreateFolder", method: "POST", path: "/api/folders", hasBody: true, decodes: true, readsBody: true,
			call: func(c *VaultwardenClient) error { _, err := c.CreateFolder("2.a|b|c"); return err }},
		{name: "ListFolders", method: "GET", path: "/api/folders", decodes: true,
			call: func(c *VaultwardenClient) error { _, err := c.ListFolders(); return err }},
		{name: "DeleteFolder", method: "DELETE", path: "/api/folders/" + opFolderID,
			call: func(c *VaultwardenClient) error { return c.DeleteFolder(opFolderID) }},
	}
}

// opFake returns a fake with the cipher and folder the ops act on, plus a
// logged-in client.
func opFake(t *testing.T) (*fakeBW, *VaultwardenClient) {
	t.Helper()
	f := newFakeBW(t)
	if id := f.seedCipher("Op Cipher", false, "2026-01-01T00:00:00Z"); id != opCipherID {
		t.Fatalf("seeded cipher id = %q, want %q", id, opCipherID)
	}
	f.folders[opFolderID] = FolderResponse{ID: opFolderID, Name: "2.a|b|c"}
	f.folderOrder = append(f.folderOrder, opFolderID)
	return f, f.client()
}

// TestClientOperationFailureMatrix runs every authenticated API call through
// the same set of server misbehaviours.
func TestClientOperationFailureMatrix(t *testing.T) {
	for _, op := range clientOps() {
		t.Run(op.name, func(t *testing.T) {
			t.Run("succeeds", func(t *testing.T) {
				f, c := opFake(t)
				if err := op.call(c); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got := f.seen(op.method, op.path)
				if len(got) != 1 {
					t.Fatalf("server saw %d %s %s requests, want 1", len(got), op.method, op.path)
				}
				if got[0].Auth != "Bearer access-0" {
					t.Errorf("Authorization = %q, want the login token", got[0].Auth)
				}
			})

			t.Run("invalid base URL", func(t *testing.T) {
				_, c := opFake(t)
				c.baseURL = invalidBaseURL
				wantErr(t, op.call(c), "creating")
			})

			t.Run("server unreachable", func(t *testing.T) {
				f, c := opFake(t)
				f.srv.Close()
				wantErr(t, op.call(c), "request failed")
			})

			t.Run("expired token is refreshed and the call retried", func(t *testing.T) {
				f, c := opFake(t)
				f.expireToken()
				if err := op.call(c); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got := f.seen(op.method, op.path)
				if len(got) != 2 {
					t.Fatalf("server saw %d requests, want 2 (original + retry)", len(got))
				}
				if got[0].Auth != "Bearer access-0" || got[1].Auth != "Bearer access-1" {
					t.Errorf("Authorization headers = %q then %q, want old then refreshed token", got[0].Auth, got[1].Auth)
				}
				if op.hasBody {
					if len(got[0].Body) == 0 {
						t.Fatal("first request had no body")
					}
					if !bytes.Equal(got[0].Body, got[1].Body) {
						t.Errorf("retry body differs from original:\n first: %s\n retry: %s", got[0].Body, got[1].Body)
					}
				}
				if n := len(f.seen("POST", "/identity/connect/token")); n != 2 {
					t.Errorf("token endpoint hit %d times, want 2 (login + refresh)", n)
				}
			})

			t.Run("expired token and refresh rejected", func(t *testing.T) {
				f, c := opFake(t)
				f.expireToken()
				f.rejectRefresh = true
				wantErr(t, op.call(c), "token refresh failed")
				if n := len(f.seen(op.method, op.path)); n != 1 {
					t.Errorf("server saw %d requests, want 1 (no retry after failed refresh)", n)
				}
			})

			t.Run("connection lost on the retry", func(t *testing.T) {
				f, c := opFake(t)
				f.expireToken()
				f.setIntercept(on(op.method, op.path, func(w http.ResponseWriter, n int) {
					if n == 1 {
						http.Error(w, "expired", http.StatusUnauthorized)
						return
					}
					killConn(w)
				}))
				wantErr(t, op.call(c), "after refresh failed")
			})

			t.Run("server error includes status and body", func(t *testing.T) {
				f, c := opFake(t)
				f.setIntercept(on(op.method, op.path, func(w http.ResponseWriter, _ int) {
					http.Error(w, "kaboom-detail", http.StatusInternalServerError)
				}))
				err := op.call(c)
				wantErr(t, err, "status 500")
				wantErr(t, err, "kaboom-detail")
			})

			if op.decodes {
				t.Run("malformed JSON response", func(t *testing.T) {
					f, c := opFake(t)
					f.setIntercept(on(op.method, op.path, func(w http.ResponseWriter, _ int) {
						_, _ = w.Write([]byte("{definitely not json"))
					}))
					wantErr(t, op.call(c), "decoding")
				})
			}

			if op.readsBody {
				t.Run("response body cut short", func(t *testing.T) {
					f, c := opFake(t)
					f.setIntercept(on(op.method, op.path, func(w http.ResponseWriter, _ int) { truncatedBody(w) }))
					wantErr(t, op.call(c), "reading response")
				})
			}
		})
	}
}

func TestClientOperationResults(t *testing.T) {
	t.Run("delete removes the cipher, 204 is accepted", func(t *testing.T) {
		f, c := opFake(t)
		if err := c.DeleteOrgCipher(opCipherID); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ids := f.cipherIDs(); len(ids) != 0 {
			t.Errorf("ciphers left on server: %v", ids)
		}

		f.setIntercept(on("DELETE", "/api/ciphers/gone", func(w http.ResponseWriter, _ int) {
			w.WriteHeader(http.StatusNoContent)
		}))
		if err := c.DeleteCipher("gone"); err != nil {
			t.Errorf("204 must be treated as success, got %v", err)
		}
	})

	t.Run("collections are listed and assigned", func(t *testing.T) {
		f, c := opFake(t)
		f.collections = []CollectionResponse{{ID: "col-1", OrganizationID: f.orgID, Name: "enc-1"}, {ID: "col-2", Name: "enc-2"}}
		got, err := c.ListOrgCollections(f.orgID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 || got[0].ID != "col-1" || got[1].Name != "enc-2" {
			t.Errorf("collections = %+v", got)
		}

		if err := c.UpdateCipherCollections(opCipherID, []string{"col-2"}, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := f.cipherCollections[opCipherID]; len(got) != 1 || got[0] != "col-2" {
			t.Errorf("server-side collections = %v, want [col-2]", got)
		}
	})

	t.Run("folders are created, listed and deleted", func(t *testing.T) {
		f, c := opFake(t)
		created, err := c.CreateFolder("2.enc|name|mac")
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if created.ID == "" || created.Name != "2.enc|name|mac" {
			t.Errorf("created folder = %+v", created)
		}
		list, err := c.ListFolders()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) != 2 || list[1].ID != created.ID {
			t.Errorf("folders = %+v, want seeded + created", list)
		}
		if err := c.DeleteFolder(created.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, ok := f.folders[created.ID]; ok {
			t.Error("folder still present after delete")
		}
		wantErr(t, c.DeleteFolder(created.ID), "delete folder returned status 404")
	})

	t.Run("org create sends collection IDs alongside the cipher", func(t *testing.T) {
		f, c := opFake(t)
		resp, err := c.CreateOrgCipher(&CipherRequest{Type: cipherTypeLogin, Name: "n", OrganizationID: f.orgID}, []string{"col-9"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.CollectionIDs) != 1 || resp.CollectionIDs[0] != "col-9" {
			t.Errorf("collection IDs = %v, want [col-9]", resp.CollectionIDs)
		}
		if resp.OrganizationID != f.orgID {
			t.Errorf("organization = %q, want %q", resp.OrganizationID, f.orgID)
		}
	})
}

// TestClientConcurrentSyncAndRefresh guards the locking contract of
// setAuthHeader: doSync reads the access token while RefreshAuth replaces it.
// Run with -race; an unlocked read in doSync is reported as a data race.
func TestClientConcurrentSyncAndRefresh(t *testing.T) {
	f := newFakeBW(t)
	c := f.client()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if _, err := c.ListCiphers(); err != nil {
					errs <- fmt.Errorf("ListCiphers: %w", err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if err := c.RefreshAuth(); err != nil {
					errs <- fmt.Errorf("RefreshAuth: %w", err)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
