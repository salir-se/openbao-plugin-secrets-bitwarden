// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package vaultwarden

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestPathSyncStatusNonExistent(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
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

func TestPathSyncStatusUnsynced(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create a role but don't sync it.
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/grafana",
		Storage:   storage,
		Data: map[string]interface{}{
			"source_path": "secret/data/grafana",
			"cipher_name": "Grafana Admin",
			"cipher_type": 1,
			"user_field":  "username",
			"pass_field":  "password",
		},
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sync/grafana",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Data["role"] != "grafana" {
		t.Errorf("role = %v, want 'grafana'", resp.Data["role"])
	}
	if resp.Data["cipher_name"] != "Grafana Admin" {
		t.Errorf("cipher_name = %v, want 'Grafana Admin'", resp.Data["cipher_name"])
	}
	if resp.Data["synced"] != false {
		t.Errorf("synced = %v, want false", resp.Data["synced"])
	}
	if resp.Data["cipher_id"] != "" {
		t.Errorf("cipher_id = %v, want empty", resp.Data["cipher_id"])
	}
	if resp.Data["source_path"] != "secret/data/grafana" {
		t.Errorf("source_path = %v, want 'secret/data/grafana'", resp.Data["source_path"])
	}
}

func TestPathSyncStatusSynced(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create a role and simulate it being synced.
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/grafana",
		Storage:   storage,
		Data: map[string]interface{}{
			"source_path": "secret/data/grafana",
			"cipher_name": "Grafana Admin",
		},
	})

	role, _ := b.readRole(ctx, storage, "grafana")
	role.CipherID = "cipher-abc-123"
	role.SyncedAt = "2026-03-30T12:00:00Z"
	b.writeRole(ctx, storage, role)

	// No Vaultwarden config, so it won't try to fetch revision_date.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sync/grafana",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Data["synced"] != true {
		t.Errorf("synced = %v, want true", resp.Data["synced"])
	}
	if resp.Data["cipher_id"] != "cipher-abc-123" {
		t.Errorf("cipher_id = %v, want 'cipher-abc-123'", resp.Data["cipher_id"])
	}
	if resp.Data["synced_at"] != "2026-03-30T12:00:00Z" {
		t.Errorf("synced_at = %v, want '2026-03-30T12:00:00Z'", resp.Data["synced_at"])
	}
}

func TestPathSyncListEmpty(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "sync/",
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
}

func TestPathSyncListWithRoles(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create two roles.
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/grafana",
		Storage:   storage,
		Data: map[string]interface{}{
			"source_path": "secret/data/grafana",
			"cipher_name": "Grafana Admin",
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

	// Mark one as synced.
	role, _ := b.readRole(ctx, storage, "grafana")
	role.CipherID = "cipher-123"
	role.SyncedAt = "2026-03-30T12:00:00Z"
	b.writeRole(ctx, storage, role)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "sync/",
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
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	keyInfo, ok := resp.Data["key_info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected key_info in response")
	}

	grafanaInfo, ok := keyInfo["grafana"].(map[string]interface{})
	if !ok {
		t.Fatal("expected grafana in key_info")
	}
	if grafanaInfo["synced"] != true {
		t.Errorf("grafana synced = %v, want true", grafanaInfo["synced"])
	}
	if grafanaInfo["cipher_id"] != "cipher-123" {
		t.Errorf("grafana cipher_id = %v, want 'cipher-123'", grafanaInfo["cipher_id"])
	}

	pgInfo, ok := keyInfo["postgres"].(map[string]interface{})
	if !ok {
		t.Fatal("expected postgres in key_info")
	}
	if pgInfo["synced"] != false {
		t.Errorf("postgres synced = %v, want false", pgInfo["synced"])
	}
}

func TestPathRolesListWithKeyInfo(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create two roles.
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/grafana",
		Storage:   storage,
		Data: map[string]interface{}{
			"source_path": "secret/data/grafana",
			"cipher_name": "Grafana Admin",
			"cipher_type": 1,
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

	// Mark grafana as synced.
	role, _ := b.readRole(ctx, storage, "grafana")
	role.CipherID = "cipher-xyz"
	role.SyncedAt = "2026-03-30T10:00:00Z"
	b.writeRole(ctx, storage, role)

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
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	keyInfo, ok := resp.Data["key_info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected key_info in response")
	}

	grafanaInfo, ok := keyInfo["grafana"].(map[string]interface{})
	if !ok {
		t.Fatal("expected grafana in key_info")
	}
	if grafanaInfo["synced"] != true {
		t.Errorf("grafana synced = %v, want true", grafanaInfo["synced"])
	}
	if grafanaInfo["cipher_id"] != "cipher-xyz" {
		t.Errorf("grafana cipher_id = %v, want 'cipher-xyz'", grafanaInfo["cipher_id"])
	}
	if grafanaInfo["cipher_name"] != "Grafana Admin" {
		t.Errorf("grafana cipher_name = %v, want 'Grafana Admin'", grafanaInfo["cipher_name"])
	}
	if grafanaInfo["synced_at"] != "2026-03-30T10:00:00Z" {
		t.Errorf("grafana synced_at = %v, want '2026-03-30T10:00:00Z'", grafanaInfo["synced_at"])
	}

	pgInfo, ok := keyInfo["postgres"].(map[string]interface{})
	if !ok {
		t.Fatal("expected postgres in key_info")
	}
	if pgInfo["synced"] != false {
		t.Errorf("postgres synced = %v, want false", pgInfo["synced"])
	}
	if pgInfo["cipher_id"] != "" {
		t.Errorf("postgres cipher_id = %v, want empty", pgInfo["cipher_id"])
	}
}
