// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// getTestBackend creates a test backend with in-memory storage.
func getTestBackend(t *testing.T) (*vaultwardenBackend, logical.Storage) {
	t.Helper()

	config := &logical.BackendConfig{
		Logger: hclog.NewNullLogger(),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 0,
			MaxLeaseTTLVal:     0,
		},
	}

	b := newBackend(config.Logger)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	storage := &logical.InmemStorage{}
	return b, storage
}

func TestPathConfig(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	t.Run("read empty config", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil {
			t.Error("expected nil response for empty config")
		}
	})

	t.Run("write config", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"url":             "https://vault.example.com",
				"email":           "admin@example.com",
				"password":        "secret-master-password",
				"organization_id": "org-123",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("unexpected error response: %v", resp.Error())
		}
	})

	t.Run("read config hides password", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp.Data["url"] != "https://vault.example.com" {
			t.Errorf("url = %v, want 'https://vault.example.com'", resp.Data["url"])
		}
		if resp.Data["email"] != "admin@example.com" {
			t.Errorf("email = %v, want 'admin@example.com'", resp.Data["email"])
		}
		if resp.Data["organization_id"] != "org-123" {
			t.Errorf("organization_id = %v, want 'org-123'", resp.Data["organization_id"])
		}
		if _, ok := resp.Data["password"]; ok {
			t.Error("password should not be returned in read response")
		}
	})

	t.Run("update config", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"url":             "https://vault2.example.com",
				"email":           "admin@example.com",
				"password":        "new-password",
				"organization_id": "org-456",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("unexpected error response: %v", resp.Error())
		}

		// Verify update.
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.Data["url"] != "https://vault2.example.com" {
			t.Errorf("url = %v, want 'https://vault2.example.com'", resp.Data["url"])
		}
		if resp.Data["organization_id"] != "org-456" {
			t.Errorf("organization_id = %v, want 'org-456'", resp.Data["organization_id"])
		}
	})

	t.Run("delete config", func(t *testing.T) {
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "config",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil {
			t.Error("expected nil response after delete")
		}
	})

	t.Run("validation - missing url", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"email":    "admin@example.com",
				"password": "secret",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || !resp.IsError() {
			t.Error("expected error response for missing url")
		}
	})

	t.Run("validation - missing email", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"url":      "https://vault.example.com",
				"password": "secret",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || !resp.IsError() {
			t.Error("expected error response for missing email")
		}
	})

	t.Run("validation - missing password", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"url":   "https://vault.example.com",
				"email": "admin@example.com",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || !resp.IsError() {
			t.Error("expected error response for missing password")
		}
	})
}

func TestPathRoles(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	t.Run("list empty", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ListOperation,
			Path:      "roles/",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Empty list returns nil or response with nil/empty keys.
		if resp != nil {
			if keys, ok := resp.Data["keys"].([]string); ok && len(keys) > 0 {
				t.Error("expected empty list")
			}
		}
	})

	t.Run("create role", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/grafana",
			Storage:   storage,
			Data: map[string]interface{}{
				"source_path":    "secret/data/grafana",
				"cipher_name":    "Grafana Admin",
				"cipher_type":    1,
				"url_field":      "url",
				"user_field":     "username",
				"pass_field":     "password",
				"collection_ids": "col-1,col-2",
				"notes_template": "Managed by OpenBao",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("unexpected error response: %v", resp.Error())
		}
	})

	t.Run("read role", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/grafana",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		if resp.Data["name"] != "grafana" {
			t.Errorf("name = %v, want 'grafana'", resp.Data["name"])
		}
		if resp.Data["source_path"] != "secret/data/grafana" {
			t.Errorf("source_path = %v, want 'secret/data/grafana'", resp.Data["source_path"])
		}
		if resp.Data["cipher_name"] != "Grafana Admin" {
			t.Errorf("cipher_name = %v, want 'Grafana Admin'", resp.Data["cipher_name"])
		}
		if resp.Data["cipher_type"] != 1 {
			t.Errorf("cipher_type = %v, want 1", resp.Data["cipher_type"])
		}
		if resp.Data["url_field"] != "url" {
			t.Errorf("url_field = %v, want 'url'", resp.Data["url_field"])
		}
		if resp.Data["user_field"] != "username" {
			t.Errorf("user_field = %v, want 'username'", resp.Data["user_field"])
		}
		if resp.Data["pass_field"] != "password" {
			t.Errorf("pass_field = %v, want 'password'", resp.Data["pass_field"])
		}
		if resp.Data["notes_template"] != "Managed by OpenBao" {
			t.Errorf("notes_template = %v, want 'Managed by OpenBao'", resp.Data["notes_template"])
		}

		collIDs, ok := resp.Data["collection_ids"].([]string)
		if !ok {
			t.Fatalf("collection_ids type = %T, want []string", resp.Data["collection_ids"])
		}
		if len(collIDs) != 2 || collIDs[0] != "col-1" || collIDs[1] != "col-2" {
			t.Errorf("collection_ids = %v, want [col-1, col-2]", collIDs)
		}
	})

	t.Run("list roles", func(t *testing.T) {
		// Create a second role.
		b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/postgres",
			Storage:   storage,
			Data: map[string]interface{}{
				"source_path": "secret/data/postgres",
				"cipher_name": "PostgreSQL",
			},
		})

		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ListOperation,
			Path:      "roles/",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}

		keys := resp.Data["keys"].([]string)
		if len(keys) != 2 {
			t.Errorf("expected 2 roles, got %d", len(keys))
		}
	})

	t.Run("update role", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/grafana",
			Storage:   storage,
			Data: map[string]interface{}{
				"source_path":    "secret/data/grafana",
				"cipher_name":    "Grafana Admin Updated",
				"notes_template": "Updated notes",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("unexpected error response: %v", resp.Error())
		}

		// Verify update.
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/grafana",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Data["cipher_name"] != "Grafana Admin Updated" {
			t.Errorf("cipher_name = %v, want 'Grafana Admin Updated'", resp.Data["cipher_name"])
		}
	})

	t.Run("delete role", func(t *testing.T) {
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "roles/postgres",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/postgres",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil {
			t.Error("expected nil response for deleted role")
		}
	})

	t.Run("read non-existent role", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/nonexistent",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil {
			t.Error("expected nil response for non-existent role")
		}
	})

	t.Run("validation - missing source_path", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/bad",
			Storage:   storage,
			Data: map[string]interface{}{
				"cipher_name": "Test",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || !resp.IsError() {
			t.Error("expected error response for missing source_path")
		}
	})

	t.Run("validation - missing cipher_name", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/bad",
			Storage:   storage,
			Data: map[string]interface{}{
				"source_path": "secret/data/test",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || !resp.IsError() {
			t.Error("expected error response for missing cipher_name")
		}
	})
}

func TestPathConfigBaoFields(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	t.Run("write config with bao_token and bao_addr", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"url":       "https://vault.example.com",
				"email":     "admin@example.com",
				"password":  "secret",
				"bao_token": "s.my-root-token",
				"bao_addr":  "http://127.0.0.1:8200",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("unexpected error response: %v", resp.Error())
		}
	})

	t.Run("read config hides bao_token", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := resp.Data["bao_token"]; ok {
			t.Error("bao_token should not be returned in read response")
		}
		if _, ok := resp.Data["password"]; ok {
			t.Error("password should not be returned in read response")
		}
	})

	t.Run("read config shows bao_addr", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Data["bao_addr"] != "http://127.0.0.1:8200" {
			t.Errorf("bao_addr = %v, want 'http://127.0.0.1:8200'", resp.Data["bao_addr"])
		}
	})

	t.Run("bao_token persists in storage", func(t *testing.T) {
		config, err := b.readConfig(ctx, storage)
		if err != nil {
			t.Fatalf("readConfig failed: %v", err)
		}
		if config.BaoToken != "s.my-root-token" {
			t.Errorf("BaoToken = %v, want 's.my-root-token'", config.BaoToken)
		}
		if config.BaoAddr != "http://127.0.0.1:8200" {
			t.Errorf("BaoAddr = %v, want 'http://127.0.0.1:8200'", config.BaoAddr)
		}
	})

	t.Run("partial update preserves bao_token", func(t *testing.T) {
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"url":      "https://vault2.example.com",
				"email":    "admin@example.com",
				"password": "new-password",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		config, err := b.readConfig(ctx, storage)
		if err != nil {
			t.Fatalf("readConfig failed: %v", err)
		}
		if config.BaoToken != "s.my-root-token" {
			t.Errorf("BaoToken lost after partial update: %v", config.BaoToken)
		}
		if config.BaoAddr != "http://127.0.0.1:8200" {
			t.Errorf("BaoAddr lost after partial update: %v", config.BaoAddr)
		}
		if config.URL != "https://vault2.example.com" {
			t.Errorf("URL not updated: %v", config.URL)
		}
	})

	t.Run("clear organization_id with empty string", func(t *testing.T) {
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"url":             "https://vault2.example.com",
				"email":           "admin@example.com",
				"password":        "secret",
				"organization_id": "",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		config, err := b.readConfig(ctx, storage)
		if err != nil {
			t.Fatalf("readConfig failed: %v", err)
		}
		if config.OrganizationID != "" {
			t.Errorf("OrganizationID should be empty, got %v", config.OrganizationID)
		}
	})
}

func TestSyncNonExistentRole(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/nonexistent",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected error response for non-existent role")
	}
}

func TestSyncNoConfig(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create a role but no config
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test",
		Storage:   storage,
		Data: map[string]interface{}{
			"source_path": "secret/data/test",
			"cipher_name": "Test",
		},
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync/test",
		Storage:   storage,
	})
	// Should fail because no Vaultwarden config exists
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Error("expected error when syncing without config")
	}
}

func TestSyncAllEmpty(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sync",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Syncing with no roles should return an error
	if resp == nil || !resp.IsError() {
		t.Error("expected error response when no roles defined")
	}
}

func TestConfigInvalidationClearsClient(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Write initial config
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":      "https://vault.example.com",
			"email":    "admin@example.com",
			"password": "secret",
		},
	})

	// Simulate a cached client
	b.mu.Lock()
	b.client = &VaultwardenClient{}
	b.mu.Unlock()

	// Update config — should invalidate client
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":      "https://vault2.example.com",
			"email":    "admin@example.com",
			"password": "new-secret",
		},
	})

	// Trigger invalidation (simulating what OpenBao does)
	b.invalidate(ctx, "config")

	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.client != nil {
		t.Error("client should be nil after config update + invalidation")
	}
}

func TestBackendInvalidation(t *testing.T) {
	b, _ := getTestBackend(t)

	// Manually set a client.
	b.mu.Lock()
	b.client = &VaultwardenClient{}
	b.mu.Unlock()

	// Invalidate.
	b.invalidate(context.Background(), "config")

	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.client != nil {
		t.Error("client should be nil after config invalidation")
	}
}

func TestBackendInvalidationNonConfig(t *testing.T) {
	b, _ := getTestBackend(t)

	// Manually set a client.
	b.mu.Lock()
	b.client = &VaultwardenClient{}
	b.mu.Unlock()

	// Invalidate with a non-config key — should not clear client.
	b.invalidate(context.Background(), "role/something")

	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.client == nil {
		t.Error("client should not be nil after non-config invalidation")
	}
}

func TestFactory(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: hclog.NewNullLogger(),
		System: &logical.StaticSystemView{},
	}

	backend, err := Factory(ctx, conf)
	if err != nil {
		t.Fatalf("Factory failed: %v", err)
	}
	if backend == nil {
		t.Error("expected non-nil backend")
	}
}

func TestSealWrapPaths(t *testing.T) {
	b, _ := getTestBackend(t)

	special := b.SpecialPaths()
	if special == nil || len(special.SealWrapStorage) == 0 {
		t.Fatal("expected SealWrapStorage paths")
	}

	found := map[string]bool{"config": false, "role/*": false}
	for _, p := range special.SealWrapStorage {
		if _, ok := found[p]; ok {
			found[p] = true
		}
	}

	for k, v := range found {
		if !v {
			t.Errorf("expected %q in SealWrapStorage paths", k)
		}
	}
}
