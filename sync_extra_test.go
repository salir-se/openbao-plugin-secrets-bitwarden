// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// decFields decrypts a cipher's custom fields into a name -> value map.
func (f *fakeBW) decFields(fields []CipherFieldData, org bool) map[string]string {
	out := map[string]string{}
	for _, fd := range fields {
		out[f.dec(fd.Name, org)] = f.dec(fd.Value, org)
	}
	return out
}

func grafanaSecret() map[string]interface{} {
	return map[string]interface{}{
		"username": "admin",
		"password": "s3cret",
		"url":      "https://grafana.example.com",
		"api_key":  "abc123",
		"port":     3000,
	}
}

func TestSyncPersonalLoginCipher(t *testing.T) {
	e := newSyncEnv(t, false)
	e.bao.put("secret/data/grafana", grafanaSecret())
	e.loginRole("grafana", map[string]interface{}{
		"extra_urls":     "https://a.example.com,https://b.example.com",
		"notes_template": "Managed by OpenBao",
		"folder_id":      "folder-7",
	})

	resp := e.mustOK(e.do(logical.UpdateOperation, "sync/grafana", nil))
	id, _ := resp.Data["cipher_id"].(string)
	if id == "" {
		t.Fatalf("no cipher_id in response: %+v", resp.Data)
	}
	if resp.Data["cipher_name"] != "Cipher grafana" {
		t.Errorf("cipher_name = %v", resp.Data["cipher_name"])
	}

	if n := len(e.bw.seen("POST", "/api/ciphers")); n != 1 {
		t.Fatalf("personal create endpoint hit %d times, want 1", n)
	}
	if n := len(e.bw.seen("POST", "/api/ciphers/create")); n != 0 {
		t.Errorf("org create endpoint must not be used without an organization, hit %d times", n)
	}

	body := e.bw.body(id)
	if body.Type != cipherTypeLogin || body.OrganizationID != "" || body.FolderID != "folder-7" {
		t.Errorf("type=%d org=%q folder=%q", body.Type, body.OrganizationID, body.FolderID)
	}
	if got := e.bw.dec(body.Name, false); got != "Cipher grafana" {
		t.Errorf("name = %q", got)
	}
	if got := e.bw.dec(body.Notes, false); got != "Managed by OpenBao" {
		t.Errorf("notes = %q", got)
	}
	if body.Login == nil {
		t.Fatal("login data missing")
	}
	if got := e.bw.dec(body.Login.Username, false); got != "admin" {
		t.Errorf("username = %q", got)
	}
	if got := e.bw.dec(body.Login.Password, false); got != "s3cret" {
		t.Errorf("password = %q", got)
	}
	var uris []string
	for _, u := range body.Login.URIs {
		if u.Match != nil {
			t.Errorf("URI match = %v, want null (default matching)", *u.Match)
		}
		uris = append(uris, e.bw.dec(u.URI, false))
	}
	wantURIs := []string{"https://grafana.example.com", "https://a.example.com", "https://b.example.com"}
	if strings.Join(uris, " ") != strings.Join(wantURIs, " ") {
		t.Errorf("URIs = %v, want %v", uris, wantURIs)
	}

	// Known limitation (pinned): every KV key that is not mapped to a
	// structured field is synced as a visible text custom field.
	fields := e.bw.decFields(body.Fields, false)
	if len(fields) != 2 || fields["api_key"] != "abc123" || fields["port"] != "3000" {
		t.Errorf("custom fields = %v, want api_key and port only", fields)
	}
	for _, fd := range body.Fields {
		if fd.Type != 0 {
			t.Errorf("custom field type = %d, want 0 (text)", fd.Type)
		}
	}

	// No plaintext secret may appear in what was sent to the server.
	for _, r := range e.bw.seen("POST", "/api/ciphers") {
		for _, secret := range []string{"s3cret", "abc123", "grafana.example.com", "Cipher grafana"} {
			if strings.Contains(string(r.Body), secret) {
				t.Errorf("request body contains plaintext %q", secret)
			}
		}
	}

	role := e.role("grafana")
	if role.CipherID != id {
		t.Errorf("role cipher_id = %q, want %q", role.CipherID, id)
	}
	if _, err := time.Parse(time.RFC3339, role.SyncedAt); err != nil {
		t.Errorf("synced_at %q is not RFC3339: %v", role.SyncedAt, err)
	}

	t.Run("second sync updates in place", func(t *testing.T) {
		secret := grafanaSecret()
		secret["password"] = "rotated"
		e.bao.put("secret/data/grafana", secret)

		resp := e.mustOK(e.do(logical.UpdateOperation, "sync/grafana", nil))
		if resp.Data["cipher_id"] != id {
			t.Errorf("cipher_id changed from %q to %v", id, resp.Data["cipher_id"])
		}
		if n := len(e.bw.seen("PUT", "/api/ciphers/"+id)); n != 1 {
			t.Errorf("personal update endpoint hit %d times, want 1", n)
		}
		if ids := e.bw.cipherIDs(); len(ids) != 1 {
			t.Errorf("server has %d ciphers, want 1", len(ids))
		}
		if got := e.bw.dec(e.bw.body(id).Login.Password, false); got != "rotated" {
			t.Errorf("password after update = %q, want rotated", got)
		}
	})

	t.Run("status reports the server revision date", func(t *testing.T) {
		resp := e.mustOK(e.do(logical.ReadOperation, "sync/grafana", nil))
		if resp.Data["synced"] != true || resp.Data["cipher_id"] != id {
			t.Errorf("status = %+v", resp.Data)
		}
		e.bw.mu.Lock()
		want := e.bw.ciphers[id].RevisionDate
		e.bw.mu.Unlock()
		if resp.Data["revision_date"] != want {
			t.Errorf("revision_date = %v, want %v", resp.Data["revision_date"], want)
		}
	})

	t.Run("status surfaces a server error without failing", func(t *testing.T) {
		e.bw.setIntercept(on("GET", "/api/ciphers/"+id, func(w http.ResponseWriter, _ int) {
			http.Error(w, "gone", http.StatusNotFound)
		}))
		defer e.bw.setIntercept(nil)
		resp := e.mustOK(e.do(logical.ReadOperation, "sync/grafana", nil))
		msg, _ := resp.Data["vaultwarden_error"].(string)
		if !strings.Contains(msg, "status 404") {
			t.Errorf("vaultwarden_error = %q", msg)
		}
		if _, ok := resp.Data["revision_date"]; ok {
			t.Error("revision_date must be absent when the lookup failed")
		}
	})
}

func TestSyncOrganizationCipher(t *testing.T) {
	e := newSyncEnv(t, true)
	e.bao.put("secret/data/db", map[string]interface{}{"username": "pg", "password": "pw"})
	e.loginRole("db", map[string]interface{}{"collection_ids": "col-a,col-b"})

	resp := e.mustOK(e.do(logical.UpdateOperation, "sync/db", nil))
	id := resp.Data["cipher_id"].(string)

	creates := e.bw.seen("POST", "/api/ciphers/create")
	if len(creates) != 1 {
		t.Fatalf("org create endpoint hit %d times, want 1", len(creates))
	}
	var sent orgCipherCreateRequest
	if err := json.Unmarshal(creates[0].Body, &sent); err != nil {
		t.Fatalf("decoding create body: %v", err)
	}
	if strings.Join(sent.CollectionIDs, ",") != "col-a,col-b" {
		t.Errorf("collection IDs = %v", sent.CollectionIDs)
	}
	if sent.Cipher.OrganizationID != e.bw.orgID {
		t.Errorf("organization = %q", sent.Cipher.OrganizationID)
	}

	body := e.bw.body(id)
	if got := e.bw.dec(body.Name, true); got != "Cipher db" {
		t.Errorf("name decrypted with org key = %q", got)
	}
	if _, err := DecryptCipherString(body.Name, e.bw.symKey[:32], e.bw.symKey[32:]); err == nil {
		t.Error("org cipher must not be decryptable with the personal key")
	}
	if got := e.bw.dec(body.Login.Password, true); got != "pw" {
		t.Errorf("password = %q", got)
	}
	if len(body.Login.URIs) != 0 {
		t.Errorf("no URI expected when the secret has no url key, got %d", len(body.Login.URIs))
	}

	// Updates of org ciphers must go through the admin endpoint.
	e.mustOK(e.do(logical.UpdateOperation, "sync/db", nil))
	if n := len(e.bw.seen("PUT", "/api/ciphers/"+id+"/admin")); n != 1 {
		t.Errorf("admin update endpoint hit %d times, want 1", n)
	}
	if n := len(e.bw.seen("PUT", "/api/ciphers/"+id)); n != 0 {
		t.Errorf("non-admin update endpoint hit %d times, want 0", n)
	}
}

// Known limitation (pinned): a role without a cipher ID adopts any existing
// item with the same decrypted name, and deletes all other items of that
// name, keeping the one with the newest revision date.
func TestSyncAdoptsByNameAndDeletesDuplicates(t *testing.T) {
	for _, org := range []bool{true, false} {
		name := "personal"
		if org {
			name = "organization"
		}
		t.Run(name, func(t *testing.T) {
			e := newSyncEnv(t, org)
			e.bao.put("secret/data/dup", map[string]interface{}{"username": "u", "password": "p"})
			e.loginRole("dup", nil)

			old := e.bw.seedCipher("Cipher dup", org, "2026-01-01T00:00:00Z")
			newest := e.bw.seedCipher("Cipher dup", org, "2026-03-01T00:00:00Z")
			mid := e.bw.seedCipher("Cipher dup", org, "2026-02-01T00:00:00Z")
			unrelated := e.bw.seedCipher("Something else", org, "2026-04-01T00:00:00Z")

			resp := e.mustOK(e.do(logical.UpdateOperation, "sync/dup", nil))
			if resp.Data["cipher_id"] != newest {
				t.Fatalf("adopted %v, want newest %s", resp.Data["cipher_id"], newest)
			}

			ids := e.bw.cipherIDs()
			sort.Strings(ids)
			want := []string{newest, unrelated}
			sort.Strings(want)
			if strings.Join(ids, ",") != strings.Join(want, ",") {
				t.Errorf("remaining ciphers = %v, want %v", ids, want)
			}

			suffix := ""
			if org {
				suffix = "/admin"
			}
			for _, id := range []string{old, mid} {
				if n := len(e.bw.seen("DELETE", "/api/ciphers/"+id+suffix)); n != 1 {
					t.Errorf("duplicate %s: %d delete requests on the expected endpoint, want 1", id, n)
				}
			}
			if got := e.bw.dec(e.bw.body(newest).Login.Username, org); got != "u" {
				t.Errorf("adopted cipher was not updated with the secret, username = %q", got)
			}
		})
	}
}

func TestSyncContinuesWhenDuplicateDeleteFails(t *testing.T) {
	e := newSyncEnv(t, false)
	e.bao.put("secret/data/dup", map[string]interface{}{"password": "p"})
	e.loginRole("dup", nil)
	old := e.bw.seedCipher("Cipher dup", false, "2026-01-01T00:00:00Z")
	newest := e.bw.seedCipher("Cipher dup", false, "2026-02-01T00:00:00Z")

	e.bw.setIntercept(on("DELETE", "/api/ciphers/"+old, func(w http.ResponseWriter, _ int) {
		http.Error(w, "locked", http.StatusForbidden)
	}))

	resp := e.mustOK(e.do(logical.UpdateOperation, "sync/dup", nil))
	if resp.Data["cipher_id"] != newest {
		t.Errorf("cipher_id = %v, want %s", resp.Data["cipher_id"], newest)
	}
	if ids := e.bw.cipherIDs(); len(ids) != 2 {
		t.Errorf("the undeletable duplicate should still exist, ciphers = %v", ids)
	}
}

func TestSyncCreatesWhenNameLookupFails(t *testing.T) {
	e := newSyncEnv(t, true)
	e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
	e.loginRole("svc", nil)
	existing := e.bw.seedCipher("Cipher svc", true, "2026-01-01T00:00:00Z")

	// First /api/sync (org key fetch) works, the lookup by name does not.
	calls := 0
	e.bw.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "GET" || r.URL.Path != "/api/sync" {
			return false
		}
		calls++
		if calls == 1 {
			return false
		}
		http.Error(w, "overloaded", http.StatusServiceUnavailable)
		return true
	})

	resp := e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil))
	if resp.Data["cipher_id"] == existing {
		t.Error("existing cipher must not be adopted when the lookup failed")
	}
	if n := len(e.bw.seen("POST", "/api/ciphers/create")); n != 1 {
		t.Errorf("create endpoint hit %d times, want 1", n)
	}
}

// Known limitation (pinned): any update error, not only "not found", makes
// the plugin create a new cipher and forget the old ID.
func TestSyncFallsBackToCreateWhenUpdateFails(t *testing.T) {
	for _, org := range []bool{true, false} {
		e := newSyncEnv(t, org)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)

		role := e.role("svc")
		role.CipherID = "deleted-on-server"
		if err := e.b.writeRole(e.ctx, e.storage, role); err != nil {
			t.Fatalf("writeRole: %v", err)
		}

		resp := e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil))
		id := resp.Data["cipher_id"].(string)
		if id == "deleted-on-server" || id == "" {
			t.Fatalf("org=%v: cipher_id = %q, want a newly created one", org, id)
		}
		if got := e.role("svc").CipherID; got != id {
			t.Errorf("org=%v: role cipher_id = %q, want %q", org, got, id)
		}
	}
}

func TestSyncCreateFailureResetsClient(t *testing.T) {
	e := newSyncEnv(t, false)
	e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
	e.loginRole("svc", nil)
	e.bw.setIntercept(on("POST", "/api/ciphers", func(w http.ResponseWriter, _ int) {
		http.Error(w, "quota exceeded", http.StatusPaymentRequired)
	}))

	_, err := e.do(logical.UpdateOperation, "sync/svc", nil)
	wantErr(t, err, `syncing role "svc"`)
	wantErr(t, err, "creating cipher")
	wantErr(t, err, "quota exceeded")
	if e.cachedClient() != nil {
		t.Error("cached client must be dropped after a failed sync")
	}
	if got := e.role("svc").CipherID; got != "" {
		t.Errorf("role cipher_id = %q after failed create, want empty", got)
	}
}

func TestSyncRecoversAfterRoleSaveFailure(t *testing.T) {
	e := newSyncEnv(t, false)
	e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
	e.loginRole("svc", nil)

	healthy := e.storage
	e.storage = &faultStorage{Storage: healthy, onPut: failOn("role/svc")}
	_, err := e.do(logical.UpdateOperation, "sync/svc", nil)
	wantErr(t, err, "failed to save ID to role")
	wantErr(t, err, "will recover on retry")

	ids := e.bw.cipherIDs()
	if len(ids) != 1 {
		t.Fatalf("server has %d ciphers after the failed save, want 1", len(ids))
	}

	// With storage healthy again the orphan is found by name, not duplicated.
	e.storage = healthy
	resp := e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil))
	if resp.Data["cipher_id"] != ids[0] {
		t.Errorf("retry produced %v, want the orphaned cipher %s", resp.Data["cipher_id"], ids[0])
	}
	if got := e.bw.cipherIDs(); len(got) != 1 {
		t.Errorf("server has %d ciphers after retry, want 1", len(got))
	}
}

func TestSyncSetupFailures(t *testing.T) {
	t.Run("wrong master password", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.loginRole("svc", nil)
		e.reconfigure(map[string]interface{}{"password": "wrong"})
		_, err := e.do(logical.UpdateOperation, "sync/svc", nil)
		wantErr(t, err, "getting client")
		wantErr(t, err, "login failed")
		if e.bao.count() != 0 {
			t.Error("the source secret must not be read when login fails")
		}
	})

	t.Run("config unreadable after client is cached", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil))

		e.storage = &faultStorage{Storage: e.storage, onGet: failOn("config")}
		_, err := e.do(logical.UpdateOperation, "sync/svc", nil)
		wantErr(t, err, "reading config")
	})

	t.Run("role unreadable", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.storage = &faultStorage{Storage: e.storage, onGet: failOn("role/svc")}
		for _, op := range []logical.Operation{logical.UpdateOperation, logical.ReadOperation, logical.DeleteOperation} {
			_, err := e.do(op, "sync/svc", nil)
			wantErr(t, err, "reading role from storage")
		}
	})

	t.Run("unknown organization", func(t *testing.T) {
		e := newSyncEnv(t, true)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		e.reconfigure(map[string]interface{}{"organization_id": "org-nope"})
		_, err := e.do(logical.UpdateOperation, "sync/svc", nil)
		wantErr(t, err, "getting org encryption keys")
		if n := e.bw.writes(); n != 0 {
			t.Errorf("%d cipher writes with an unusable org key, want 0", n)
		}
	})

	t.Run("missing source secret", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.loginRole("svc", nil)
		_, err := e.do(logical.UpdateOperation, "sync/svc", nil)
		wantErr(t, err, `reading source secret at "secret/data/svc"`)
		wantErr(t, err, "secret not found")
		if n := e.bw.writes(); n != 0 {
			t.Errorf("%d cipher writes without a source secret, want 0", n)
		}
	})
}

func TestReadSourceSecret(t *testing.T) {
	t.Run("config unreadable", func(t *testing.T) {
		e := newSyncEnv(t, false)
		st := &faultStorage{Storage: e.storage, onGet: failOn("config")}
		_, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: st}, "secret/data/x")
		wantErr(t, err, "reading config")
	})

	t.Run("no token anywhere", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.reconfigure(map[string]interface{}{"bao_token": nil})
		_, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage}, "secret/data/x")
		wantErr(t, err, "no token available")
		if e.bao.count() != 0 {
			t.Error("no request expected without a token")
		}
	})

	t.Run("caller token is used when no bao_token is configured", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.reconfigure(map[string]interface{}{"bao_token": nil})
		e.bao.put("secret/data/x", map[string]interface{}{"k": "v"})
		got, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage, ClientToken: e.bao.token}, "secret/data/x")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got["k"] != "v" {
			t.Errorf("data = %v", got)
		}
	})

	// Known limitation (pinned): the configured bao_token is used for every
	// read regardless of who called the plugin (confused deputy on
	// source_path); the caller's own token is ignored when it is set.
	t.Run("configured bao_token overrides the caller token", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/x", map[string]interface{}{"k": "v"})
		_, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage, ClientToken: "caller-token"}, "secret/data/x")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := e.bao.seenTokens(); len(got) != 1 || got[0] != e.bao.token {
			t.Errorf("tokens presented to OpenBao = %v, want only the configured one", got)
		}
	})

	t.Run("permission denied", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.reconfigure(map[string]interface{}{"bao_token": "not-allowed"})
		_, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage}, "secret/data/x")
		wantErr(t, err, `reading from "secret/data/x"`)
		wantErr(t, err, "permission denied")
	})

	t.Run("KV v1 data is returned as is", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.v1["kv1/app"] = map[string]interface{}{"user": "u", "pass": "p"}
		got, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage}, "kv1/app")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 || got["user"] != "u" || got["pass"] != "p" {
			t.Errorf("data = %v", got)
		}
	})

	t.Run("KV v2 data is unwrapped", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/app", map[string]interface{}{"user": "u"})
		got, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage}, "secret/data/app")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, hasMeta := got["metadata"]; hasMeta || got["user"] != "u" {
			t.Errorf("data = %v, want only the inner data map", got)
		}
	})

	// Known limitation (pinned): bao_addr is stored without validation, so
	// a malformed address only surfaces when a sync is attempted.
	t.Run("malformed bao_addr", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.reconfigure(map[string]interface{}{"bao_addr": "http://bad\x7fhost"})
		_, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage}, "secret/data/x")
		wantErr(t, err, "creating OpenBao client")
	})
}

func TestReadSourceSecretTLSVerification(t *testing.T) {
	// The OpenBao API client honours these process-wide variables; make sure
	// the developer's shell cannot change what this test asserts.
	for _, v := range []string{"BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY", "BAO_CACERT", "VAULT_CACERT", "BAO_CAPATH", "VAULT_CAPATH", "BAO_CACERT_BYTES", "VAULT_CACERT_BYTES"} {
		t.Setenv(v, "")
	}

	setup := func(t *testing.T, overrides map[string]interface{}) (*syncEnv, *fakeBao) {
		e := newSyncEnv(t, false)
		tlsBao := newFakeBao(t, true) // self-signed certificate
		tlsBao.put("secret/data/x", map[string]interface{}{"k": "v"})
		cfg := map[string]interface{}{"bao_addr": tlsBao.url(), "bao_token": tlsBao.token}
		for k, v := range overrides {
			cfg[k] = v
		}
		e.reconfigure(cfg)
		return e, tlsBao
	}

	t.Run("untrusted certificate is rejected by default", func(t *testing.T) {
		e, tlsBao := setup(t, nil)
		_, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage}, "secret/data/x")
		wantErr(t, err, "certificate")
		if tlsBao.count() != 0 {
			t.Errorf("OpenBao handled %d requests over an unverified connection, want 0", tlsBao.count())
		}
	})

	t.Run("explicit false behaves like the default", func(t *testing.T) {
		e, _ := setup(t, map[string]interface{}{"bao_tls_skip_verify": false})
		_, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage}, "secret/data/x")
		wantErr(t, err, "certificate")
	})

	t.Run("bao_tls_skip_verify=true accepts it", func(t *testing.T) {
		e, tlsBao := setup(t, map[string]interface{}{"bao_tls_skip_verify": true})
		got, err := e.b.readSourceSecret(e.ctx, &logical.Request{Storage: e.storage}, "secret/data/x")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got["k"] != "v" || tlsBao.count() != 1 {
			t.Errorf("data = %v, requests = %d", got, tlsBao.count())
		}
	})
}

func TestSyncAllReportsPartialFailure(t *testing.T) {
	e := newSyncEnv(t, false)
	e.bao.put("secret/data/good", map[string]interface{}{"password": "p"})
	e.bao.put("secret/data/also-good", map[string]interface{}{"password": "q"})
	e.loginRole("good", nil)
	e.loginRole("missing-secret", nil)
	e.loginRole("also-good", nil)
	putRaw(t, e.storage, "role/corrupt", "{not json")

	resp := e.mustOK(e.do(logical.UpdateOperation, "sync", nil))
	if resp.Data["total"] != 4 || resp.Data["synced"] != 2 || resp.Data["failed"] != 2 {
		t.Fatalf("totals = total:%v synced:%v failed:%v, want 4/2/2", resp.Data["total"], resp.Data["synced"], resp.Data["failed"])
	}
	results := resp.Data["results"].(map[string]interface{})

	for _, name := range []string{"good", "also-good"} {
		r := results[name].(map[string]interface{})
		if r["status"] != "synced" || r["cipher_id"] == "" {
			t.Errorf("%s: %+v", name, r)
		}
		if e.role(name).CipherID == "" {
			t.Errorf("%s: role has no cipher_id after sync-all", name)
		}
	}
	missing := results["missing-secret"].(map[string]interface{})
	if missing["status"] != "error" || !strings.Contains(missing["error"].(string), "secret not found") {
		t.Errorf("missing-secret: %+v", missing)
	}
	corrupt := results["corrupt"].(map[string]interface{})
	if corrupt["status"] != "error" || !strings.Contains(corrupt["error"].(string), "reading role") {
		t.Errorf("corrupt: %+v", corrupt)
	}
	if ids := e.bw.cipherIDs(); len(ids) != 2 {
		t.Errorf("server has %d ciphers, want 2", len(ids))
	}

	t.Run("list shows state and flags the corrupt role", func(t *testing.T) {
		resp := e.mustOK(e.do(logical.ListOperation, "sync/", nil))
		info := resp.Data["key_info"].(map[string]interface{})
		if got := info["good"].(map[string]interface{}); got["synced"] != true {
			t.Errorf("good: %+v", got)
		}
		if got := info["missing-secret"].(map[string]interface{}); got["synced"] != false {
			t.Errorf("missing-secret: %+v", got)
		}
		if got := info["corrupt"].(map[string]interface{}); !strings.Contains(got["error"].(string), "failed to read") {
			t.Errorf("corrupt: %+v", got)
		}

		resp = e.mustOK(e.do(logical.ListOperation, "roles/", nil))
		info = resp.Data["key_info"].(map[string]interface{})
		if got := info["corrupt"].(map[string]interface{}); !strings.Contains(got["error"].(string), "failed to read") {
			t.Errorf("roles list, corrupt: %+v", got)
		}
	})
}

func TestSyncAndRoleListStorageFailure(t *testing.T) {
	e := newSyncEnv(t, false)
	e.storage = &faultStorage{Storage: e.storage, onList: failOn("role/")}
	for _, tc := range []struct {
		op   logical.Operation
		path string
	}{
		{logical.UpdateOperation, "sync"},
		{logical.ListOperation, "sync/"},
		{logical.ListOperation, "roles/"},
	} {
		_, err := e.do(tc.op, tc.path, nil)
		wantErr(t, err, "listing roles")
	}
}

func TestSyncDelete(t *testing.T) {
	t.Run("unknown role", func(t *testing.T) {
		e := newSyncEnv(t, false)
		resp, err := e.do(logical.DeleteOperation, "sync/nope", nil)
		wantErrResp(t, resp, err, `role "nope" not found`)
	})

	t.Run("role without a synced cipher", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.loginRole("svc", nil)
		resp, err := e.do(logical.DeleteOperation, "sync/svc", nil)
		wantErrResp(t, resp, err, "has no synced cipher")
	})

	for _, org := range []bool{false, true} {
		name := "personal cipher is removed, role kept"
		if org {
			name = "organization cipher is removed via the admin endpoint"
		}
		t.Run(name, func(t *testing.T) {
			e := newSyncEnv(t, org)
			e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
			e.loginRole("svc", nil)
			id := e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil)).Data["cipher_id"].(string)

			resp := e.mustOK(e.do(logical.DeleteOperation, "sync/svc", nil))
			if resp.Data["deleted_cipher_id"] != id || resp.Data["role"] != "svc" {
				t.Errorf("response = %+v", resp.Data)
			}
			if ids := e.bw.cipherIDs(); len(ids) != 0 {
				t.Errorf("ciphers left on server: %v", ids)
			}
			path := "/api/ciphers/" + id
			if org {
				path += "/admin"
			}
			if n := len(e.bw.seen("DELETE", path)); n != 1 {
				t.Errorf("%d DELETE requests on %s, want 1", n, path)
			}
			role := e.role("svc")
			if role.CipherID != "" {
				t.Errorf("role cipher_id = %q, want cleared", role.CipherID)
			}
			if role.SourcePath != "secret/data/svc" {
				t.Errorf("role definition was altered: %+v", role)
			}
		})
	}

	t.Run("server refuses the delete", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		id := e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil)).Data["cipher_id"].(string)

		e.bw.setIntercept(on("DELETE", "/api/ciphers/"+id, func(w http.ResponseWriter, _ int) {
			http.Error(w, "nope", http.StatusForbidden)
		}))
		_, err := e.do(logical.DeleteOperation, "sync/svc", nil)
		wantErr(t, err, `deleting cipher for role "svc"`)
		wantErr(t, err, "status 403")
		if e.cachedClient() != nil {
			t.Error("cached client must be dropped after a failed delete")
		}
		if got := e.role("svc").CipherID; got != id {
			t.Errorf("role cipher_id = %q, want it kept as %q", got, id)
		}
	})

	t.Run("login failure", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil))
		e.reconfigure(map[string]interface{}{"password": "wrong"})
		_, err := e.do(logical.DeleteOperation, "sync/svc", nil)
		wantErr(t, err, "getting client")
	})

	t.Run("config unreadable", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil))
		e.storage = &faultStorage{Storage: e.storage, onGet: failOn("config")}
		_, err := e.do(logical.DeleteOperation, "sync/svc", nil)
		wantErr(t, err, "reading config")
		if ids := e.bw.cipherIDs(); len(ids) != 1 {
			t.Errorf("cipher must not be deleted when config cannot be read, ciphers = %v", ids)
		}
	})

	// Pinned behaviour: if the cipher is deleted but the role cannot be
	// saved, the call still reports success and the role keeps a stale ID.
	t.Run("role save failure after delete is not reported", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		id := e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil)).Data["cipher_id"].(string)

		healthy := e.storage
		e.storage = &faultStorage{Storage: healthy, onPut: failOn("role/svc")}
		e.mustOK(e.do(logical.DeleteOperation, "sync/svc", nil))
		e.storage = healthy
		if ids := e.bw.cipherIDs(); len(ids) != 0 {
			t.Errorf("ciphers left on server: %v", ids)
		}
		if got := e.role("svc").CipherID; got != id {
			t.Errorf("stored role cipher_id = %q, want the stale %q", got, id)
		}
	})

	t.Run("nothing to delete is a no-op", func(t *testing.T) {
		e := newSyncEnv(t, false)
		if err := e.b.deleteCipherForRole(e.ctx, e.storage, &roleEntry{Name: "x"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n := len(e.bw.requests); n != 0 {
			t.Errorf("%d requests sent for a role without a cipher, want 0", n)
		}
	})
}

func TestPeriodicSyncDisabledStates(t *testing.T) {
	req := func(e *syncEnv) *logical.Request { return &logical.Request{Storage: e.storage} }

	t.Run("not configured", func(t *testing.T) {
		b, storage := getTestBackend(t)
		if err := b.periodicSync(t.Context(), &logical.Request{Storage: storage}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, interval := range []string{"", "0", "0s", "-5m", "soon"} {
		t.Run("interval "+interval, func(t *testing.T) {
			e := newSyncEnv(t, false)
			e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
			e.loginRole("svc", nil)
			if interval != "" {
				e.reconfigure(map[string]interface{}{"sync_interval": interval})
			}
			if err := e.b.periodicSync(e.ctx, req(e)); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if e.bao.count() != 0 || e.bw.writes() != 0 {
				t.Errorf("periodic sync ran with interval %q (bao reads=%d, cipher writes=%d)", interval, e.bao.count(), e.bw.writes())
			}
		})
	}

	t.Run("interval not yet elapsed", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		e.reconfigure(map[string]interface{}{"sync_interval": "1h"})
		e.b.mu.Lock()
		e.b.lastSync = time.Now().Add(-30 * time.Minute)
		e.b.mu.Unlock()
		if err := e.b.periodicSync(e.ctx, req(e)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if e.bao.count() != 0 {
			t.Error("periodic sync ran before the interval elapsed")
		}
	})

	t.Run("no roles", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.reconfigure(map[string]interface{}{"sync_interval": "1m"})
		if err := e.b.periodicSync(e.ctx, req(e)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !e.b.lastSync.IsZero() {
			t.Error("lastSync must stay unset when there is nothing to sync")
		}
	})

	t.Run("role listing fails", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		e.reconfigure(map[string]interface{}{"sync_interval": "1m"})
		st := &faultStorage{Storage: e.storage, onList: failOn("role/")}
		if err := e.b.periodicSync(e.ctx, &logical.Request{Storage: st}); err != nil {
			t.Fatalf("periodic sync must swallow storage errors, got %v", err)
		}
		if e.bao.count() != 0 || !e.b.lastSync.IsZero() {
			t.Error("nothing may be synced or recorded when roles cannot be listed")
		}
	})

	t.Run("config unreadable", func(t *testing.T) {
		e := newSyncEnv(t, false)
		st := &faultStorage{Storage: e.storage, onGet: failOn("config")}
		if err := e.b.periodicSync(e.ctx, &logical.Request{Storage: st}); err != nil {
			t.Fatalf("periodic sync must swallow storage errors, got %v", err)
		}
	})
}

func TestPeriodicSyncChangeDetection(t *testing.T) {
	e := newSyncEnv(t, false)
	e.reconfigure(map[string]interface{}{"sync_interval": "1ns"})
	e.bao.put("secret/data/a", map[string]interface{}{"password": "a1"})
	e.bao.put("secret/data/b", map[string]interface{}{"password": "b1"})
	e.loginRole("a", nil)
	e.loginRole("b", nil)
	e.loginRole("no-secret", nil)
	putRaw(t, e.storage, "role/corrupt", "{not json")
	req := &logical.Request{Storage: e.storage}

	run := func() {
		t.Helper()
		time.Sleep(time.Millisecond) // let the 1ns interval elapse
		if err := e.b.periodicSync(e.ctx, req); err != nil {
			t.Fatalf("periodicSync: %v", err)
		}
	}

	run()
	if n := e.bw.writes(); n != 2 {
		t.Fatalf("first run made %d cipher writes, want 2 (a and b)", n)
	}
	idA, idB := e.role("a").CipherID, e.role("b").CipherID
	if idA == "" || idB == "" {
		t.Fatalf("roles not synced: a=%q b=%q", idA, idB)
	}
	if e.b.lastSync.IsZero() {
		t.Error("lastSync not recorded")
	}

	t.Run("status and info report the periodic sync", func(t *testing.T) {
		resp := e.mustOK(e.do(logical.ReadOperation, "status", nil))
		if _, err := time.Parse(time.RFC3339, resp.Data["last_periodic_sync"].(string)); err != nil {
			t.Errorf("last_periodic_sync = %v", resp.Data["last_periodic_sync"])
		}
		resp = e.mustOK(e.do(logical.ReadOperation, "info", nil))
		if resp.Data["sync_interval"] != "1ns" || resp.Data["synced_roles"] != 2 || resp.Data["total_roles"] != 4 {
			t.Errorf("info = interval:%v synced:%v total:%v", resp.Data["sync_interval"], resp.Data["synced_roles"], resp.Data["total_roles"])
		}
		if _, err := time.Parse(time.RFC3339, resp.Data["last_sync"].(string)); err != nil {
			t.Errorf("last_sync = %v", resp.Data["last_sync"])
		}
	})

	t.Run("unchanged secrets are skipped", func(t *testing.T) {
		before, reads := e.bw.writes(), e.bao.count()
		run()
		if n := e.bw.writes(); n != before {
			t.Errorf("unchanged data caused %d cipher writes", n-before)
		}
		if e.bao.count() == reads {
			t.Error("source secrets must still be read to detect changes")
		}
	})

	t.Run("only the changed secret is pushed", func(t *testing.T) {
		e.bao.put("secret/data/a", map[string]interface{}{"password": "a2"})
		before := e.bw.writes()
		run()
		if n := e.bw.writes() - before; n != 1 {
			t.Fatalf("%d cipher writes after changing one secret, want 1", n)
		}
		if n := len(e.bw.seen("PUT", "/api/ciphers/"+idA)); n != 1 {
			t.Errorf("cipher a updated %d times, want 1", n)
		}
		if got := e.bw.dec(e.bw.body(idA).Login.Password, false); got != "a2" {
			t.Errorf("password of a = %q, want a2", got)
		}
		if n := len(e.bw.seen("PUT", "/api/ciphers/"+idB)); n != 0 {
			t.Errorf("unchanged cipher b updated %d times", n)
		}
	})

	t.Run("a failed push is retried on the next run", func(t *testing.T) {
		e.bao.put("secret/data/b", map[string]interface{}{"password": "b2"})
		// Updating fails and so does the create fallback.
		e.bw.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
			if strings.HasPrefix(r.URL.Path, "/api/ciphers") && (r.Method == "PUT" || r.Method == "POST") {
				http.Error(w, "maintenance", http.StatusServiceUnavailable)
				return true
			}
			return false
		})
		run()
		if e.cachedClient() != nil {
			t.Error("cached client must be dropped after a failed periodic sync")
		}

		e.bw.setIntercept(nil)
		run()
		id := e.role("b").CipherID
		if got := e.bw.dec(e.bw.body(id).Login.Password, false); got != "b2" {
			t.Errorf("password of b after retry = %q, want b2", got)
		}
	})
}

func TestComputeDataHash(t *testing.T) {
	a := computeDataHash(map[string]interface{}{"user": "u", "pass": "p", "n": 1})
	b := computeDataHash(map[string]interface{}{"n": 1, "pass": "p", "user": "u"})
	if a != b {
		t.Error("hash must not depend on map iteration order")
	}
	if a == computeDataHash(map[string]interface{}{"user": "u", "pass": "P", "n": 1}) {
		t.Error("hash must change when a value changes")
	}
	if a == computeDataHash(map[string]interface{}{"user": "u", "pass": "p"}) {
		t.Error("hash must change when a key is removed")
	}
	if computeDataHash(nil) != computeDataHash(map[string]interface{}{}) {
		t.Error("nil and empty data must hash the same")
	}
}
