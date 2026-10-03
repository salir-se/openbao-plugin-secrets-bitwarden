// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// existence runs the framework's existence check for a path.
func existence(t *testing.T, b *vaultwardenBackend, s logical.Storage, path string) (bool, error) {
	t.Helper()
	found, exists, err := b.HandleExistenceCheck(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      path,
		Storage:   s,
	})
	if err == nil && !found {
		t.Fatalf("no existence check registered for %q", path)
	}
	return exists, err
}

func TestConfigExistenceCheck(t *testing.T) {
	e := newSyncEnv(t, false)
	if exists, err := existence(t, e.b, e.storage, "config"); err != nil || !exists {
		t.Errorf("configured backend: exists=%v err=%v, want true", exists, err)
	}

	b, storage := getTestBackend(t)
	if exists, err := existence(t, b, storage, "config"); err != nil || exists {
		t.Errorf("fresh backend: exists=%v err=%v, want false", exists, err)
	}

	_, err := existence(t, b, &faultStorage{Storage: storage, onGet: failOn("config")}, "config")
	wantErr(t, err, "checking config existence")
}

func TestConfigValidationAndStorageErrors(t *testing.T) {
	full := map[string]interface{}{"url": "https://vault.example.com", "email": "a@example.com", "password": "pw"}

	for _, missing := range []string{"url", "email", "password"} {
		t.Run("missing "+missing, func(t *testing.T) {
			b, storage := getTestBackend(t)
			data := map[string]interface{}{}
			for k, v := range full {
				if k != missing {
					data[k] = v
				}
			}
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: "config", Storage: storage, Data: data,
			})
			wantErrResp(t, resp, err, missing+" is required")
			if entry, _ := storage.Get(context.Background(), "config"); entry != nil {
				t.Error("an invalid config must not be stored")
			}
		})
	}

	t.Run("storage failures", func(t *testing.T) {
		e := newSyncEnv(t, false)
		healthy := e.storage

		e.storage = &faultStorage{Storage: healthy, onGet: failOn("config")}
		_, err := e.do(logical.ReadOperation, "config", nil)
		wantErr(t, err, "reading config from storage")
		_, err = e.do(logical.UpdateOperation, "config", full)
		wantErr(t, err, "reading config from storage")

		e.storage = &faultStorage{Storage: healthy, onPut: failOn("config")}
		_, err = e.do(logical.UpdateOperation, "config", full)
		wantErr(t, err, "storing config")

		e.storage = &faultStorage{Storage: healthy, onDelete: failOn("config")}
		_, err = e.do(logical.DeleteOperation, "config", nil)
		wantErr(t, err, "deleting config")
	})

	t.Run("corrupt stored config", func(t *testing.T) {
		b, storage := getTestBackend(t)
		putRaw(t, storage, "config", "{not json")
		_, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "config", Storage: storage})
		wantErr(t, err, "decoding config")
	})

	t.Run("delete removes the config and the cached client", func(t *testing.T) {
		e := newSyncEnv(t, false)
		if _, err := e.b.getClient(e.ctx, e.storage); err != nil {
			t.Fatalf("getClient: %v", err)
		}
		e.mustOK(e.do(logical.DeleteOperation, "config", nil))
		if e.cachedClient() != nil {
			t.Error("cached client must be dropped when the config is deleted")
		}
		if resp, err := e.do(logical.ReadOperation, "config", nil); err != nil || resp != nil {
			t.Errorf("read after delete = (%+v, %v), want (nil, nil)", resp, err)
		}
		_, err := e.b.getClient(e.ctx, e.storage)
		wantErr(t, err, "plugin not configured")
	})

	// Known limitation (pinned): updating url or bao_addr keeps the stored
	// password and bao_token, so the old credentials are sent to the new host.
	t.Run("partial update keeps stored credentials", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.mustOK(e.do(logical.UpdateOperation, "config", map[string]interface{}{"url": "https://other.example.com"}))
		cfg, err := e.b.readConfig(e.ctx, e.storage)
		if err != nil {
			t.Fatalf("readConfig: %v", err)
		}
		if cfg.URL != "https://other.example.com" || cfg.Password != e.bw.password || cfg.BaoToken != e.bao.token {
			t.Errorf("config after partial update = url:%q password kept:%v token kept:%v", cfg.URL, cfg.Password == e.bw.password, cfg.BaoToken == e.bao.token)
		}
	})
}

func TestConfigBaoTLSSkipVerify(t *testing.T) {
	e := newSyncEnv(t, false)

	read := func() map[string]interface{} {
		t.Helper()
		return e.mustOK(e.do(logical.ReadOperation, "config", nil)).Data
	}

	if got := read()["bao_tls_skip_verify"]; got != false {
		t.Fatalf("default bao_tls_skip_verify = %v, want false", got)
	}

	e.mustOK(e.do(logical.UpdateOperation, "config", map[string]interface{}{"bao_tls_skip_verify": true}))
	if got := read()["bao_tls_skip_verify"]; got != true {
		t.Fatalf("after enabling: %v, want true", got)
	}

	// Updating an unrelated field must not silently change it.
	e.mustOK(e.do(logical.UpdateOperation, "config", map[string]interface{}{"sync_interval": "5m"}))
	if got := read()["bao_tls_skip_verify"]; got != true {
		t.Errorf("after unrelated update: %v, want it to stay true", got)
	}

	e.mustOK(e.do(logical.UpdateOperation, "config", map[string]interface{}{"bao_tls_skip_verify": false}))
	if got := read()["bao_tls_skip_verify"]; got != false {
		t.Errorf("after disabling: %v, want false", got)
	}

	data := read()
	for _, secret := range []string{"password", "bao_token"} {
		if _, ok := data[secret]; ok {
			t.Errorf("config read must not return %q", secret)
		}
	}

	t.Run("config stored before the field existed decodes to false", func(t *testing.T) {
		b, storage := getTestBackend(t)
		putRaw(t, storage, "config", `{"url":"https://vault.example.com","email":"a@example.com","password":"pw","organization_id":"","bao_token":"t","bao_addr":"https://bao.example.com","sync_interval":"10m"}`)
		cfg, err := b.readConfig(context.Background(), storage)
		if err != nil {
			t.Fatalf("readConfig: %v", err)
		}
		if cfg.BaoTLSSkipVerify {
			t.Error("legacy config must decode with TLS verification enabled")
		}
		resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "config", Storage: storage})
		if err != nil || resp.Data["bao_tls_skip_verify"] != false {
			t.Errorf("read of legacy config = (%+v, %v)", resp, err)
		}
	})
}

// fieldMapping ties a role field to the JSON name of the cipher attribute it
// fills.
type fieldMapping struct {
	roleField string
	jsonName  string
	set       func(r *roleEntry, v string)
}

func cardMappings() []fieldMapping {
	return []fieldMapping{
		{"cardholder_name_field", "cardholderName", func(r *roleEntry, v string) { r.CardholderNameField = v }},
		{"brand_field", "brand", func(r *roleEntry, v string) { r.BrandField = v }},
		{"number_field", "number", func(r *roleEntry, v string) { r.NumberField = v }},
		{"exp_month_field", "expMonth", func(r *roleEntry, v string) { r.ExpMonthField = v }},
		{"exp_year_field", "expYear", func(r *roleEntry, v string) { r.ExpYearField = v }},
		{"code_field", "code", func(r *roleEntry, v string) { r.CodeField = v }},
	}
}

func identityMappings() []fieldMapping {
	return []fieldMapping{
		{"title_field", "title", func(r *roleEntry, v string) { r.TitleField = v }},
		{"first_name_field", "firstName", func(r *roleEntry, v string) { r.FirstNameField = v }},
		{"middle_name_field", "middleName", func(r *roleEntry, v string) { r.MiddleNameField = v }},
		{"last_name_field", "lastName", func(r *roleEntry, v string) { r.LastNameField = v }},
		{"email_field", "email", func(r *roleEntry, v string) { r.EmailField = v }},
		{"phone_field", "phone", func(r *roleEntry, v string) { r.PhoneField = v }},
		{"company_field", "company", func(r *roleEntry, v string) { r.CompanyField = v }},
		{"ssn_field", "ssn", func(r *roleEntry, v string) { r.SSNField = v }},
		{"identity_user_field", "username", func(r *roleEntry, v string) { r.IdentityUserField = v }},
		{"passport_number_field", "passportNumber", func(r *roleEntry, v string) { r.PassportNumberField = v }},
		{"license_number_field", "licenseNumber", func(r *roleEntry, v string) { r.LicenseNumberField = v }},
		{"address1_field", "address1", func(r *roleEntry, v string) { r.Address1Field = v }},
		{"address2_field", "address2", func(r *roleEntry, v string) { r.Address2Field = v }},
		{"address3_field", "address3", func(r *roleEntry, v string) { r.Address3Field = v }},
		{"city_field", "city", func(r *roleEntry, v string) { r.CityField = v }},
		{"state_field", "state", func(r *roleEntry, v string) { r.StateField = v }},
		{"postal_code_field", "postalCode", func(r *roleEntry, v string) { r.PostalCodeField = v }},
		{"country_field", "country", func(r *roleEntry, v string) { r.CountryField = v }},
	}
}

func loginMappings() []fieldMapping {
	return []fieldMapping{
		{"user_field", "username", func(r *roleEntry, v string) { r.UserField = v }},
		{"pass_field", "password", func(r *roleEntry, v string) { r.PassField = v }},
		{"url_field", "uri", func(r *roleEntry, v string) { r.URLField = v }},
	}
}

// decryptSection turns an encrypted cipher section (card/identity) into a
// jsonName -> plaintext map.
func decryptSection(t *testing.T, f *fakeBW, section interface{}) map[string]string {
	t.Helper()
	raw, err := json.Marshal(section)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var enc map[string]string
	if err := json.Unmarshal(raw, &enc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := map[string]string{}
	for k, v := range enc {
		out[k] = f.dec(v, false)
	}
	return out
}

// TestTypedCipherRoles drives card and identity roles through the HTTP-level
// role API and a real sync, then decrypts what reached the server.
func TestTypedCipherRoles(t *testing.T) {
	cases := []struct {
		name       string
		cipherType int
		mappings   []fieldMapping
		section    func(CipherRequest) interface{}
	}{
		{"card", cipherTypeCard, cardMappings(), func(c CipherRequest) interface{} { return c.Card }},
		{"identity", cipherTypeIdentity, identityMappings(), func(c CipherRequest) interface{} { return c.Identity }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newSyncEnv(t, false)

			roleData := map[string]interface{}{
				"source_path": "secret/data/" + tc.name,
				"cipher_name": "My " + tc.name,
				"cipher_type": tc.cipherType,
			}
			secret := map[string]interface{}{"unmapped_extra": "extra-value"}
			for _, m := range tc.mappings {
				key := "src_" + m.jsonName
				roleData[m.roleField] = key
				secret[key] = "value-of-" + m.jsonName
			}
			e.bao.put("secret/data/"+tc.name, secret)
			e.mustOK(e.do(logical.UpdateOperation, "roles/"+tc.name, roleData))

			// The role API returns exactly the mappings of this cipher type.
			read := e.mustOK(e.do(logical.ReadOperation, "roles/"+tc.name, nil)).Data
			if read["cipher_type"] != tc.cipherType {
				t.Errorf("cipher_type = %v", read["cipher_type"])
			}
			for _, m := range tc.mappings {
				if read[m.roleField] != "src_"+m.jsonName {
					t.Errorf("role read %s = %v, want src_%s", m.roleField, read[m.roleField], m.jsonName)
				}
			}
			for _, loginOnly := range []string{"user_field", "pass_field", "url_field", "extra_urls"} {
				if _, ok := read[loginOnly]; ok {
					t.Errorf("role read of a %s role must not include %s", tc.name, loginOnly)
				}
			}

			id := e.mustOK(e.do(logical.UpdateOperation, "sync/"+tc.name, nil)).Data["cipher_id"].(string)
			body := e.bw.body(id)
			if body.Type != tc.cipherType {
				t.Errorf("synced cipher type = %d, want %d", body.Type, tc.cipherType)
			}
			if body.Login != nil {
				t.Error("login section must be absent")
			}

			got := decryptSection(t, e.bw, tc.section(body))
			if len(got) != len(tc.mappings) {
				t.Errorf("section has %d attributes, want %d: %v", len(got), len(tc.mappings), got)
			}
			for _, m := range tc.mappings {
				if got[m.jsonName] != "value-of-"+m.jsonName {
					t.Errorf("%s = %q, want value-of-%s", m.jsonName, got[m.jsonName], m.jsonName)
				}
			}

			// Mapped keys are not repeated as custom fields; the unmapped one is.
			fields := e.bw.decFields(body.Fields, false)
			if len(fields) != 1 || fields["unmapped_extra"] != "extra-value" {
				t.Errorf("custom fields = %v, want only unmapped_extra", fields)
			}
		})
	}
}

func TestSecureNoteRole(t *testing.T) {
	e := newSyncEnv(t, false)
	e.bao.put("secret/data/note", map[string]interface{}{"token": "tok", "account": "SYS"})
	e.mustOK(e.do(logical.UpdateOperation, "roles/note", map[string]interface{}{
		"source_path": "secret/data/note",
		"cipher_name": "A note",
		"cipher_type": cipherTypeSecureNote,
	}))

	read := e.mustOK(e.do(logical.ReadOperation, "roles/note", nil)).Data
	for k := range read {
		if strings.HasSuffix(k, "_field") {
			t.Errorf("secure note role read includes type-specific field %q", k)
		}
	}

	id := e.mustOK(e.do(logical.UpdateOperation, "sync/note", nil)).Data["cipher_id"].(string)
	body := e.bw.body(id)
	if body.SecureNote == nil || body.SecureNote.Type != 0 {
		t.Errorf("secureNote = %+v, want type 0", body.SecureNote)
	}
	if body.Login != nil || body.Card != nil || body.Identity != nil {
		t.Error("secure note must not carry login/card/identity sections")
	}
	fields := e.bw.decFields(body.Fields, false)
	if len(fields) != 2 || fields["token"] != "tok" || fields["account"] != "SYS" {
		t.Errorf("custom fields = %v", fields)
	}
}

func TestBuildCipherRequestEdgeCases(t *testing.T) {
	b, _ := getTestBackend(t)
	encKey, macKey := randomBytes(t, 32), randomBytes(t, 32)

	t.Run("unknown cipher type gets no typed section", func(t *testing.T) {
		got, err := b.buildCipherRequest(&roleEntry{CipherName: "n", CipherType: 9}, map[string]interface{}{"k": "v"}, "", encKey, macKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Login != nil || got.Card != nil || got.Identity != nil || got.SecureNote != nil {
			t.Errorf("unexpected typed section: %+v", got)
		}
		if len(got.Fields) != 1 {
			t.Errorf("custom fields = %d, want 1", len(got.Fields))
		}
	})

	t.Run("mapped key absent from the secret is omitted and not a custom field", func(t *testing.T) {
		role := &roleEntry{CipherName: "n", CipherType: cipherTypeLogin, UserField: "username", PassField: "password"}
		got, err := b.buildCipherRequest(role, map[string]interface{}{"password": "p"}, "", encKey, macKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Login.Username != "" {
			t.Errorf("username = %q, want empty", got.Login.Username)
		}
		if len(got.Fields) != 0 || got.Notes != "" {
			t.Errorf("fields=%d notes=%q, want none", len(got.Fields), got.Notes)
		}
	})

	t.Run("no secret data yields no custom fields", func(t *testing.T) {
		got, err := b.buildCipherRequest(&roleEntry{CipherName: "n", CipherType: cipherTypeSecureNote}, nil, "org-9", encKey, macKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Fields != nil || got.OrganizationID != "org-9" {
			t.Errorf("fields=%v org=%q", got.Fields, got.OrganizationID)
		}
	})

	t.Run("unusable key", func(t *testing.T) {
		_, err := b.buildCipherRequest(&roleEntry{CipherName: "n", CipherType: cipherTypeLogin}, nil, "", encKey[:8], macKey)
		wantErr(t, err, "encrypting cipher name")
	})
}

// TestFieldEncryptionFailureNamesTheField checks that when a mapped value
// cannot be encrypted the builder stops and the error names the source key.
func TestFieldEncryptionFailureNamesTheField(t *testing.T) {
	b, _ := getTestBackend(t)
	badKey := []byte("short")
	macKey := randomBytes(t, 32)
	secret := map[string]interface{}{"the_key": "v"}

	run := func(kind string, mappings []fieldMapping, build func(r *roleEntry, known map[string]bool) (interface{}, error)) {
		for _, m := range mappings {
			t.Run(kind+"/"+m.roleField, func(t *testing.T) {
				role := &roleEntry{Name: "r"}
				m.set(role, "the_key")
				known := map[string]bool{}
				section, err := build(role, known)
				wantErr(t, err, `encrypting "the_key"`)
				if !known["the_key"] {
					t.Error("the key must still be marked as mapped")
				}
				if s, ok := section.(*CipherLoginData); ok && s != nil {
					t.Error("no partial section may be returned on error")
				}
			})
		}
	}

	run("login", loginMappings(), func(r *roleEntry, known map[string]bool) (interface{}, error) {
		return b.buildLoginData(r, secret, badKey, macKey, known)
	})
	run("card", cardMappings(), func(r *roleEntry, known map[string]bool) (interface{}, error) {
		return b.buildCardData(r, secret, badKey, macKey, known)
	})
	run("identity", identityMappings(), func(r *roleEntry, known map[string]bool) (interface{}, error) {
		return b.buildIdentityData(r, secret, badKey, macKey, known)
	})

	t.Run("login/extra_urls", func(t *testing.T) {
		_, err := b.buildLoginData(&roleEntry{ExtraURLs: []string{"https://alias.example.com"}}, secret, badKey, macKey, map[string]bool{})
		wantErr(t, err, `encrypting extra URL "https://alias.example.com"`)
	})
}

func TestRoleExistenceAndValidation(t *testing.T) {
	e := newSyncEnv(t, false)
	e.loginRole("svc", nil)

	if exists, err := existence(t, e.b, e.storage, "roles/svc"); err != nil || !exists {
		t.Errorf("existing role: exists=%v err=%v", exists, err)
	}
	if exists, err := existence(t, e.b, e.storage, "roles/other"); err != nil || exists {
		t.Errorf("missing role: exists=%v err=%v", exists, err)
	}
	_, err := existence(t, e.b, &faultStorage{Storage: e.storage, onGet: failOn("role/svc")}, "roles/svc")
	wantErr(t, err, "checking role existence")

	resp, err := e.do(logical.UpdateOperation, "roles/new", map[string]interface{}{"cipher_name": "X"})
	wantErrResp(t, resp, err, "source_path is required")
	resp, err = e.do(logical.UpdateOperation, "roles/new", map[string]interface{}{"source_path": "secret/data/x"})
	wantErrResp(t, resp, err, "cipher_name is required")
	if resp, err := e.do(logical.ReadOperation, "roles/new", nil); err != nil || resp != nil {
		t.Errorf("rejected role must not exist, read = (%+v, %v)", resp, err)
	}

	t.Run("update keeps unspecified fields and sync state", func(t *testing.T) {
		role := e.role("svc")
		role.CipherID = "cipher-77"
		role.SyncedAt = "2026-01-01T00:00:00Z"
		if err := e.b.writeRole(e.ctx, e.storage, role); err != nil {
			t.Fatalf("writeRole: %v", err)
		}
		e.mustOK(e.do(logical.UpdateOperation, "roles/svc", map[string]interface{}{"cipher_name": "Renamed"}))
		got := e.role("svc")
		if got.CipherName != "Renamed" || got.SourcePath != "secret/data/svc" || got.UserField != "username" {
			t.Errorf("role after partial update = %+v", got)
		}
		if got.CipherID != "cipher-77" || got.SyncedAt != "2026-01-01T00:00:00Z" {
			t.Errorf("sync state lost on update: id=%q synced_at=%q", got.CipherID, got.SyncedAt)
		}
	})

	t.Run("storage failures", func(t *testing.T) {
		healthy := e.storage
		defer func() { e.storage = healthy }()

		e.storage = &faultStorage{Storage: healthy, onGet: failOn("role/svc")}
		for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation} {
			_, err := e.do(op, "roles/svc", map[string]interface{}{"cipher_name": "Y"})
			wantErr(t, err, "reading role from storage")
		}

		e.storage = &faultStorage{Storage: healthy, onPut: failOn("role/svc")}
		_, err := e.do(logical.UpdateOperation, "roles/svc", map[string]interface{}{"cipher_name": "Y"})
		wantErr(t, err, "storing role")

		putRaw(t, healthy, "role/corrupt", "{not json")
		e.storage = healthy
		_, err = e.do(logical.ReadOperation, "roles/corrupt", nil)
		wantErr(t, err, "decoding role")
	})
}

func TestRoleDeleteCascade(t *testing.T) {
	setup := func(t *testing.T) (*syncEnv, string) {
		e := newSyncEnv(t, false)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		id := e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil)).Data["cipher_id"].(string)
		return e, id
	}
	gone := func(t *testing.T, e *syncEnv) {
		t.Helper()
		if resp, err := e.do(logical.ReadOperation, "roles/svc", nil); err != nil || resp != nil {
			t.Errorf("role still readable after delete: (%+v, %v)", resp, err)
		}
	}

	t.Run("deleting a synced role deletes its cipher", func(t *testing.T) {
		e, _ := setup(t)
		e.mustOK(e.do(logical.DeleteOperation, "roles/svc", nil))
		gone(t, e)
		if ids := e.bw.cipherIDs(); len(ids) != 0 {
			t.Errorf("ciphers left on server: %v", ids)
		}
	})

	t.Run("role is deleted even when the cipher cannot be", func(t *testing.T) {
		e, id := setup(t)
		e.bw.setIntercept(on("DELETE", "/api/ciphers/"+id, func(w http.ResponseWriter, _ int) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		e.mustOK(e.do(logical.DeleteOperation, "roles/svc", nil))
		gone(t, e)
		if ids := e.bw.cipherIDs(); len(ids) != 1 {
			t.Errorf("cipher should be left behind, ciphers = %v", ids)
		}
	})

	t.Run("unsynced role makes no server call", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.loginRole("svc", nil)
		e.mustOK(e.do(logical.DeleteOperation, "roles/svc", nil))
		gone(t, e)
		if n := len(e.bw.requests); n != 0 {
			t.Errorf("%d server requests for an unsynced role, want 0", n)
		}
	})

	t.Run("deleting a role that does not exist succeeds", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.mustOK(e.do(logical.DeleteOperation, "roles/ghost", nil))
	})

	t.Run("storage delete failure", func(t *testing.T) {
		e, _ := setup(t)
		e.storage = &faultStorage{Storage: e.storage, onDelete: failOn("role/svc")}
		_, err := e.do(logical.DeleteOperation, "roles/svc", nil)
		wantErr(t, err, "deleting role")
	})
}

func TestCollectionsList(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		b, storage := getTestBackend(t)
		_, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ListOperation, Path: "collections/", Storage: storage})
		wantErr(t, err, "plugin not configured")
	})

	t.Run("no organization configured", func(t *testing.T) {
		e := newSyncEnv(t, false)
		resp, err := e.do(logical.ListOperation, "collections/", nil)
		wantErrResp(t, resp, err, "organization_id not configured")
	})

	t.Run("names are decrypted with the org key", func(t *testing.T) {
		e := newSyncEnv(t, true)
		e.bw.collections = []CollectionResponse{
			{ID: "col-1", OrganizationID: e.bw.orgID, Name: mustEncrypt(t, "Services", e.bw.orgKey[:32], e.bw.orgKey[32:])},
			{ID: "col-2", OrganizationID: e.bw.orgID, Name: mustEncrypt(t, "Databases", e.bw.orgKey[:32], e.bw.orgKey[32:])},
			{ID: "col-3", OrganizationID: e.bw.orgID, Name: "not-a-cipher-string"},
		}
		resp := e.mustOK(e.do(logical.ListOperation, "collections/", nil))
		if resp.Data["total"] != 3 {
			t.Fatalf("total = %v", resp.Data["total"])
		}
		items := resp.Data["collections"].([]map[string]interface{})
		want := []string{"col-1=Services", "col-2=Databases", "col-3=not-a-cipher-string"}
		for i, it := range items {
			if got := it["id"].(string) + "=" + it["name"].(string); got != want[i] {
				t.Errorf("item %d = %s, want %s", i, got, want[i])
			}
		}
		if n := len(e.bw.seen("GET", "/api/organizations/"+e.bw.orgID+"/collections")); n != 1 {
			t.Errorf("collections endpoint hit %d times for the configured org, want 1", n)
		}
	})

	t.Run("server failure resets the client", func(t *testing.T) {
		e := newSyncEnv(t, true)
		e.bw.setIntercept(on("GET", "/api/organizations/"+e.bw.orgID+"/collections", func(w http.ResponseWriter, _ int) {
			http.Error(w, "nope", http.StatusForbidden)
		}))
		_, err := e.do(logical.ListOperation, "collections/", nil)
		wantErr(t, err, "listing collections")
		if e.cachedClient() != nil {
			t.Error("cached client must be dropped")
		}
	})

	t.Run("organization key unavailable", func(t *testing.T) {
		e := newSyncEnv(t, true)
		e.reconfigure(map[string]interface{}{"organization_id": "org-nope"})
		_, err := e.do(logical.ListOperation, "collections/", nil)
		wantErr(t, err, "getting org encryption keys")
	})

	t.Run("config unreadable", func(t *testing.T) {
		e := newSyncEnv(t, true)
		if _, err := e.b.getClient(e.ctx, e.storage); err != nil {
			t.Fatalf("getClient: %v", err)
		}
		e.storage = &faultStorage{Storage: e.storage, onGet: failOn("config")}
		_, err := e.do(logical.ListOperation, "collections/", nil)
		wantErr(t, err, "reading config from storage")
	})
}

func TestCollectionsAssign(t *testing.T) {
	assign := map[string]interface{}{"collection_ids": "col-1,col-2"}

	synced := func(t *testing.T, org bool) (*syncEnv, string) {
		e := newSyncEnv(t, org)
		e.bao.put("secret/data/svc", map[string]interface{}{"password": "p"})
		e.loginRole("svc", nil)
		id := e.mustOK(e.do(logical.UpdateOperation, "sync/svc", nil)).Data["cipher_id"].(string)
		return e, id
	}

	t.Run("unknown role", func(t *testing.T) {
		e := newSyncEnv(t, true)
		resp, err := e.do(logical.UpdateOperation, "collections/ghost/assign", assign)
		wantErrResp(t, resp, err, `role "ghost" not found`)
	})

	t.Run("role not synced yet", func(t *testing.T) {
		e := newSyncEnv(t, true)
		e.loginRole("svc", nil)
		resp, err := e.do(logical.UpdateOperation, "collections/svc/assign", assign)
		wantErrResp(t, resp, err, "has no synced cipher")
	})

	for _, org := range []bool{true, false} {
		name := "personal vault uses the plain endpoint"
		if org {
			name = "organization uses the admin endpoint"
		}
		t.Run(name, func(t *testing.T) {
			e, id := synced(t, org)
			resp := e.mustOK(e.do(logical.UpdateOperation, "collections/svc/assign", assign))
			if resp.Data["cipher_id"] != id {
				t.Errorf("cipher_id = %v", resp.Data["cipher_id"])
			}
			path := "/api/ciphers/" + id + "/collections"
			other := path + "/admin"
			if org {
				path, other = other, path
			}
			if n := len(e.bw.seen("PUT", path)); n != 1 {
				t.Errorf("%d requests on %s, want 1", n, path)
			}
			if n := len(e.bw.seen("PUT", other)); n != 0 {
				t.Errorf("%d requests on %s, want 0", n, other)
			}
			if got := strings.Join(e.bw.cipherCollections[id], ","); got != "col-1,col-2" {
				t.Errorf("server-side collections = %q", got)
			}
			if got := strings.Join(e.role("svc").CollectionIDs, ","); got != "col-1,col-2" {
				t.Errorf("role collection_ids = %q", got)
			}
		})
	}

	t.Run("server failure resets the client and leaves the role alone", func(t *testing.T) {
		e, id := synced(t, true)
		e.bw.setIntercept(on("PUT", "/api/ciphers/"+id+"/collections/admin", func(w http.ResponseWriter, _ int) {
			http.Error(w, "nope", http.StatusBadRequest)
		}))
		_, err := e.do(logical.UpdateOperation, "collections/svc/assign", assign)
		wantErr(t, err, "updating collections")
		if e.cachedClient() != nil {
			t.Error("cached client must be dropped")
		}
		if got := e.role("svc").CollectionIDs; len(got) != 0 {
			t.Errorf("role collection_ids = %v, want unchanged", got)
		}
	})

	t.Run("login failure", func(t *testing.T) {
		e, _ := synced(t, true)
		e.reconfigure(map[string]interface{}{"password": "wrong"})
		_, err := e.do(logical.UpdateOperation, "collections/svc/assign", assign)
		wantErr(t, err, "login failed")
	})

	t.Run("storage failures", func(t *testing.T) {
		e, _ := synced(t, true)
		healthy := e.storage

		e.storage = &faultStorage{Storage: healthy, onGet: failOn("role/svc")}
		_, err := e.do(logical.UpdateOperation, "collections/svc/assign", assign)
		wantErr(t, err, "reading role from storage")

		e.storage = &faultStorage{Storage: healthy, onGet: failOn("config")}
		_, err = e.do(logical.UpdateOperation, "collections/svc/assign", assign)
		wantErr(t, err, "reading config from storage")
	})

	// Pinned behaviour: the server-side assignment succeeds even when the
	// role cannot be saved; the mismatch is only logged.
	t.Run("role save failure is not reported", func(t *testing.T) {
		e, id := synced(t, true)
		healthy := e.storage
		e.storage = &faultStorage{Storage: healthy, onPut: failOn("role/svc")}
		e.mustOK(e.do(logical.UpdateOperation, "collections/svc/assign", assign))
		e.storage = healthy
		if got := strings.Join(e.bw.cipherCollections[id], ","); got != "col-1,col-2" {
			t.Errorf("server-side collections = %q", got)
		}
		if got := e.role("svc").CollectionIDs; len(got) != 0 {
			t.Errorf("stored role collection_ids = %v, want the stale empty list", got)
		}
	})
}

func TestFolders(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		b, storage := getTestBackend(t)
		for _, tc := range []struct {
			op   logical.Operation
			path string
		}{
			{logical.ListOperation, "folders/"},
			{logical.UpdateOperation, "folders/work"},
			{logical.DeleteOperation, "folders/work"},
		} {
			_, err := b.HandleRequest(context.Background(), &logical.Request{Operation: tc.op, Path: tc.path, Storage: storage})
			wantErr(t, err, "plugin not configured")
		}
	})

	t.Run("create encrypts the name with the personal key", func(t *testing.T) {
		e := newSyncEnv(t, true) // folders are personal even with an org configured
		resp := e.mustOK(e.do(logical.UpdateOperation, "folders/work", nil))
		id := resp.Data["id"].(string)
		if id == "" || resp.Data["name"] != "work" {
			t.Fatalf("response = %+v", resp.Data)
		}
		stored := e.bw.folders[id].Name
		if stored == "work" {
			t.Fatal("folder name was sent in plaintext")
		}
		if got := e.bw.dec(stored, false); got != "work" {
			t.Errorf("stored name decrypts to %q", got)
		}

		// Listing decrypts names and passes through what it cannot decrypt.
		e.bw.folders["raw"] = FolderResponse{ID: "raw", Name: "plain-or-foreign"}
		e.bw.folderOrder = append(e.bw.folderOrder, "raw")
		list := e.mustOK(e.do(logical.ListOperation, "folders/", nil))
		if list.Data["total"] != 2 {
			t.Fatalf("total = %v", list.Data["total"])
		}
		items := list.Data["folders"].([]map[string]interface{})
		if items[0]["id"] != id || items[0]["name"] != "work" || items[1]["name"] != "plain-or-foreign" {
			t.Errorf("folders = %+v", items)
		}

		// Delete addresses the folder by ID (the "name" path segment).
		e.mustOK(e.do(logical.DeleteOperation, "folders/"+id, nil))
		if _, ok := e.bw.folders[id]; ok {
			t.Error("folder still on server after delete")
		}
	})

	t.Run("server failures reset the client", func(t *testing.T) {
		for _, tc := range []struct {
			op           logical.Operation
			path         string
			method, api  string
			wantContains string
		}{
			{logical.ListOperation, "folders/", "GET", "/api/folders", "listing folders"},
			{logical.UpdateOperation, "folders/work", "POST", "/api/folders", "creating folder"},
			{logical.DeleteOperation, "folders/f-1", "DELETE", "/api/folders/f-1", "deleting folder"},
		} {
			e := newSyncEnv(t, false)
			e.bw.setIntercept(on(tc.method, tc.api, func(w http.ResponseWriter, _ int) {
				http.Error(w, "nope", http.StatusInternalServerError)
			}))
			_, err := e.do(tc.op, tc.path, nil)
			wantErr(t, err, tc.wantContains)
			wantErr(t, err, "status 500")
			if e.cachedClient() != nil {
				t.Errorf("%s: cached client must be dropped", tc.wantContains)
			}
		}
	})

	t.Run("create fails without usable keys", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.b.mu.Lock()
		e.b.client = bareClient(e.bw.url())
		e.b.mu.Unlock()
		_, err := e.do(logical.UpdateOperation, "folders/work", nil)
		wantErr(t, err, "encrypting folder name")
		if n := len(e.bw.seen("POST", "/api/folders")); n != 0 {
			t.Errorf("%d folder requests sent without encryption, want 0", n)
		}
	})
}

func TestStatusDiagnostics(t *testing.T) {
	status := func(e *syncEnv) map[string]interface{} {
		e.t.Helper()
		return e.mustOK(e.do(logical.ReadOperation, "status", nil)).Data
	}

	t.Run("healthy", func(t *testing.T) {
		e := newSyncEnv(t, false)
		got := status(e)
		if got["ok"] != true || got["configured"] != true || got["vaultwarden_reachable"] != true || got["authenticated"] != true {
			t.Errorf("status = %+v", got)
		}
		if got["last_periodic_sync"] != "" {
			t.Errorf("last_periodic_sync = %v, want empty before any run", got["last_periodic_sync"])
		}
	})

	t.Run("corrupt config", func(t *testing.T) {
		b, storage := getTestBackend(t)
		putRaw(t, storage, "config", "{not json")
		resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "status", Storage: storage})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg, _ := resp.Data["error"].(string); !strings.Contains(msg, "reading config") {
			t.Errorf("error = %q", msg)
		}
		if resp.Data["ok"] != false || resp.Data["configured"] != false {
			t.Errorf("status = %+v", resp.Data)
		}

		info, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: "info", Storage: storage})
		if err != nil || info.Data["configured"] != false {
			t.Errorf("info = (%+v, %v)", info, err)
		}
	})

	t.Run("server unhealthy", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bw.setIntercept(on("GET", "/alive", func(w http.ResponseWriter, _ int) {
			http.Error(w, "starting", http.StatusServiceUnavailable)
		}))
		got := status(e)
		if got["vaultwarden_reachable"] != false || got["ok"] != false {
			t.Errorf("status = %+v", got)
		}
		if msg, _ := got["vaultwarden_error"].(string); !strings.Contains(msg, "unexpected status: 503") {
			t.Errorf("vaultwarden_error = %q", msg)
		}
		if n := len(e.bw.seen("POST", "/identity/connect/token")); n != 0 {
			t.Errorf("login attempted against an unhealthy server (%d token requests)", n)
		}
	})

	t.Run("server unreachable", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.bw.srv.Close()
		got := status(e)
		if msg, _ := got["vaultwarden_error"].(string); !strings.Contains(msg, "connection failed") {
			t.Errorf("vaultwarden_error = %q", msg)
		}
		if got["ok"] != false || got["authenticated"] != false {
			t.Errorf("status = %+v", got)
		}
	})

	t.Run("reachable but credentials rejected", func(t *testing.T) {
		e := newSyncEnv(t, false)
		e.reconfigure(map[string]interface{}{"password": "wrong"})
		got := status(e)
		if got["vaultwarden_reachable"] != true || got["authenticated"] != false || got["ok"] != false {
			t.Errorf("status = %+v", got)
		}
		if msg, _ := got["auth_error"].(string); !strings.Contains(msg, "login failed") {
			t.Errorf("auth_error = %q", msg)
		}
	})

	// The info endpoint documents the mount path used throughout the docs.
	t.Run("info names the plugin and uses the bitwarden/ mount in examples", func(t *testing.T) {
		e := newSyncEnv(t, false)
		info := e.mustOK(e.do(logical.ReadOperation, "info", nil)).Data
		if info["plugin"] != "openbao-plugin-secrets-bitwarden" {
			t.Errorf("plugin = %v", info["plugin"])
		}
		for step, cmd := range info["quick_start"].(map[string]interface{}) {
			if !strings.Contains(cmd.(string), " bitwarden/") {
				t.Errorf("quick_start %s = %q, want the bitwarden/ mount", step, cmd)
			}
		}
	})
}

func TestGetClientCachesAndRecovers(t *testing.T) {
	e := newSyncEnv(t, false)
	first, err := e.b.getClient(e.ctx, e.storage)
	if err != nil {
		t.Fatalf("getClient: %v", err)
	}
	second, err := e.b.getClient(e.ctx, e.storage)
	if err != nil || second != first {
		t.Fatalf("second getClient returned a different client (err=%v)", err)
	}
	if n := len(e.bw.seen("POST", "/identity/connect/token")); n != 1 {
		t.Errorf("%d logins for two getClient calls, want 1", n)
	}

	e.b.resetClient()
	_, err = e.b.getClient(e.ctx, &faultStorage{Storage: e.storage, onGet: failOn("config")})
	wantErr(t, err, "reading config")

	third, err := e.b.getClient(e.ctx, e.storage)
	if err != nil || third == first {
		t.Fatalf("expected a fresh client after reset (err=%v)", err)
	}
}
