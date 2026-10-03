// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestPathStatusNoConfig(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "status",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Data["configured"] != false {
		t.Errorf("configured = %v, want false", resp.Data["configured"])
	}
	if resp.Data["ok"] != false {
		t.Errorf("ok = %v, want false", resp.Data["ok"])
	}
	if resp.Data["message"] == nil {
		t.Error("expected message about plugin not configured")
	}
}

func TestPathStatusWithConfig(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Write config pointing at a non-reachable URL.
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":      "http://127.0.0.1:19999", // nothing listening
			"email":    "admin@example.com",
			"password": "secret",
		},
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "status",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Data["configured"] != true {
		t.Errorf("configured = %v, want true", resp.Data["configured"])
	}
	if resp.Data["vaultwarden_reachable"] != false {
		t.Errorf("vaultwarden_reachable = %v, want false", resp.Data["vaultwarden_reachable"])
	}
	if resp.Data["ok"] != false {
		t.Errorf("ok = %v, want false", resp.Data["ok"])
	}
	if resp.Data["url"] != "http://127.0.0.1:19999" {
		t.Errorf("url = %v, want 'http://127.0.0.1:19999'", resp.Data["url"])
	}
}

func TestPathStatusWithMockServer(t *testing.T) {
	// Create a mock server that responds to /alive.
	mux := http.NewServeMux()
	mux.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Return 400 for everything else (login will fail).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	b, storage := getTestBackend(t)
	ctx := context.Background()

	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":      server.URL,
			"email":    "admin@example.com",
			"password": "secret",
		},
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "status",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Data["configured"] != true {
		t.Errorf("configured = %v, want true", resp.Data["configured"])
	}
	if resp.Data["vaultwarden_reachable"] != true {
		t.Errorf("vaultwarden_reachable = %v, want true", resp.Data["vaultwarden_reachable"])
	}
	// Authentication should fail (mock doesn't implement full login flow).
	if resp.Data["authenticated"] != false {
		t.Errorf("authenticated = %v, want false", resp.Data["authenticated"])
	}
	if resp.Data["ok"] != false {
		t.Errorf("ok = %v, want false (auth failed)", resp.Data["ok"])
	}
}

func TestPathRootList(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	keys, ok := resp.Data["keys"].([]string)
	if !ok {
		t.Fatal("expected keys in response")
	}
	if len(keys) != 7 {
		t.Errorf("expected 7 sections, got %d: %v", len(keys), keys)
	}

	keyInfo, ok := resp.Data["key_info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected key_info in response")
	}
	if _, ok := keyInfo["info"]; !ok {
		t.Error("expected 'info' in key_info")
	}
	if _, ok := keyInfo["status"]; !ok {
		t.Error("expected 'status' in key_info")
	}
}

func TestPathInfoRead(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "info",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Data["plugin"] != "openbao-plugin-secrets-bitwarden" {
		t.Errorf("plugin = %v, want 'openbao-plugin-secrets-bitwarden'", resp.Data["plugin"])
	}
	if resp.Data["configured"] != false {
		t.Errorf("configured = %v, want false (no config written)", resp.Data["configured"])
	}
	if resp.Data["endpoints"] == nil {
		t.Error("expected endpoints map")
	}
	if resp.Data["quick_start"] == nil {
		t.Error("expected quick_start map")
	}
}

func TestPathStatusRoleCounts(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Write config (will fail connectivity but that's fine for counting).
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":      "http://127.0.0.1:19999",
			"email":    "admin@example.com",
			"password": "secret",
		},
	})

	// Create two roles.
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/grafana",
		Storage:   storage,
		Data: map[string]interface{}{
			"source_path": "secret/data/grafana",
			"cipher_name": "Grafana",
		},
	})
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/postgres",
		Storage:   storage,
		Data: map[string]interface{}{
			"source_path": "secret/data/postgres",
			"cipher_name": "PostgreSQL",
		},
	})

	// Simulate one role having been synced by writing cipher_id directly.
	role, _ := b.readRole(ctx, storage, "grafana")
	role.CipherID = "cipher-123"
	role.SyncedAt = "2026-03-30T12:00:00Z"
	b.writeRole(ctx, storage, role)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "status",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Data["total_roles"] != 2 {
		t.Errorf("total_roles = %v, want 2", resp.Data["total_roles"])
	}
	if resp.Data["synced_roles"] != 1 {
		t.Errorf("synced_roles = %v, want 1", resp.Data["synced_roles"])
	}
	if resp.Data["unsynced_roles"] != 1 {
		t.Errorf("unsynced_roles = %v, want 1", resp.Data["unsynced_roles"])
	}
}
