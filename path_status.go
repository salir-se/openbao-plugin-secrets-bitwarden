// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Status path handler for the Vaultwarden secrets engine.
//
// Provides a single GET endpoint that reports:
//   - Plugin configuration state
//   - Vaultwarden reachability (via /alive)
//   - Authentication status
//   - Role and sync summary
//   - Last periodic sync timestamp

package vaultwarden

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathStatus returns the path configuration for the root, info, and status endpoints.
func pathStatus(b *vaultwardenBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "/?",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
				Navigation:      true,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRootList,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "list-sections",
					},
				},
			},
			HelpSynopsis:    "List available sections of the Vaultwarden secrets engine.",
			HelpDescription: "Returns the top-level navigable sections: info, status, config, roles, sync, collections, folders.",
		},
		{
			Pattern: "info$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
				Navigation:      true,
				ItemType:        "Info",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathInfoRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "read-info",
					},
				},
			},
			HelpSynopsis:    "Vaultwarden secrets engine overview and quick reference.",
			HelpDescription: "Returns available endpoints, usage examples, and current status summary. Use this as the starting point for working with the plugin.",
		},
		{
			Pattern: "status$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
				Navigation:      true,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathStatusRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "read-status",
					},
				},
			},
			HelpSynopsis:    "Check Vaultwarden connectivity and sync status.",
			HelpDescription: "Returns the plugin's configuration state, Vaultwarden reachability, authentication status, and a summary of roles and their sync state.",
		},
	}
}

// pathRootList returns the top-level sections of the plugin.
// This makes `bao list bitwarden/` work in the CLI browser and shows
// available navigation paths.
func (b *vaultwardenBackend) pathRootList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	sections := []string{
		"info",
		"status",
		"config",
		"roles/",
		"sync/",
		"collections/",
		"folders/",
	}

	keyInfo := map[string]interface{}{
		"info":         map[string]interface{}{"description": "Quick-start guide and endpoint reference"},
		"status":       map[string]interface{}{"description": "Connectivity check and sync summary"},
		"config":       map[string]interface{}{"description": "Vaultwarden connection settings"},
		"roles/":       map[string]interface{}{"description": "Role mappings (OpenBao KV → Vaultwarden cipher)"},
		"sync/":        map[string]interface{}{"description": "Sync operations and status"},
		"collections/": map[string]interface{}{"description": "Organization collections"},
		"folders/":     map[string]interface{}{"description": "Folder management"},
	}

	return logical.ListResponseWithInfo(sections, keyInfo), nil
}

// pathInfoRead returns a quick-reference overview of the plugin.
// This is the human-friendly landing page for the CLI browser.
func (b *vaultwardenBackend) pathInfoRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	// Gather live status summary.
	config, _ := b.readConfig(ctx, req.Storage)
	configured := config != nil

	var totalRoles, syncedRoles int
	entries, err := req.Storage.List(ctx, "role/")
	if err == nil {
		totalRoles = len(entries)
		for _, name := range entries {
			role, err := b.readRole(ctx, req.Storage, name)
			if err == nil && role != nil && role.CipherID != "" {
				syncedRoles++
			}
		}
	}

	b.mu.RLock()
	lastSync := b.lastSync
	b.mu.RUnlock()

	lastSyncStr := "(never)"
	if !lastSync.IsZero() {
		lastSyncStr = lastSync.UTC().Format(time.RFC3339)
	}

	syncInterval := "(disabled)"
	if configured && config.SyncInterval != "" {
		syncInterval = config.SyncInterval
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"plugin":      "openbao-plugin-secrets-bitwarden",
			"description": "Syncs secrets from OpenBao KV to Vaultwarden (Bitwarden-compatible) with client-side encryption",

			"configured":    configured,
			"total_roles":   totalRoles,
			"synced_roles":  syncedRoles,
			"sync_interval": syncInterval,
			"last_sync":     lastSyncStr,

			"endpoints": map[string]interface{}{
				"config":                   "GET/POST — Vaultwarden connection settings (url, email, password, org_id)",
				"status":                   "GET     — Connectivity check: reachability, auth, role counts",
				"roles/":                   "LIST    — All roles with sync metadata (cipher_id, synced, synced_at)",
				"roles/:name":              "CRUD    — Manage a role mapping (OpenBao KV path → Vaultwarden cipher)",
				"sync/":                    "LIST    — All roles with sync state; POST — sync ALL roles",
				"sync/:name":               "GET     — Sync status for one role; POST — force sync; DELETE — remove cipher",
				"collections/":             "LIST    — Organization collections (decrypted names)",
				"collections/:name/assign": "POST    — Assign a cipher to collections",
				"folders/":                 "LIST    — Folders; POST — create folder; DELETE — remove folder",
			},

			"quick_start": map[string]interface{}{
				"1_configure":   "bao write bitwarden/config url=https://vault.example.com email=... password=... organization_id=...",
				"2_check":       "bao read bitwarden/status",
				"3_create_role": "bao write bitwarden/roles/grafana source_path=secret/data/grafana cipher_name='Grafana Admin' user_field=username pass_field=password url_field=url",
				"4_sync":        "bao write -f bitwarden/sync/grafana",
				"5_verify":      "bao read bitwarden/sync/grafana",
				"6_list":        "bao list bitwarden/sync/",
			},
		},
	}, nil
}

// pathStatusRead checks connectivity to Vaultwarden and returns a status report.
func (b *vaultwardenBackend) pathStatusRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	result := map[string]interface{}{
		"configured":            false,
		"vaultwarden_reachable": false,
		"authenticated":         false,
		"ok":                    false,
	}

	// Step 1: Check configuration.
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		result["error"] = fmt.Sprintf("reading config: %v", err)
		return &logical.Response{Data: result}, nil
	}
	if config == nil {
		result["message"] = "plugin not configured: write to config/ first"
		return &logical.Response{Data: result}, nil
	}

	result["configured"] = true
	result["url"] = config.URL
	result["sync_interval"] = config.SyncInterval

	// Step 2: Check Vaultwarden reachability via /alive (no auth required).
	reachable, reachErr := checkVaultwardenAlive(config.URL)
	result["vaultwarden_reachable"] = reachable
	if reachErr != nil {
		result["vaultwarden_error"] = reachErr.Error()
	}

	// Step 3: Check authentication by getting/creating the client.
	if reachable {
		_, authErr := b.getClient(ctx, req.Storage)
		if authErr != nil {
			result["authenticated"] = false
			result["auth_error"] = authErr.Error()
		} else {
			result["authenticated"] = true
		}
	}

	// Step 4: Count roles and sync state.
	entries, err := req.Storage.List(ctx, "role/")
	if err == nil {
		totalRoles := len(entries)
		syncedRoles := 0
		for _, name := range entries {
			role, err := b.readRole(ctx, req.Storage, name)
			if err == nil && role != nil && role.CipherID != "" {
				syncedRoles++
			}
		}
		result["total_roles"] = totalRoles
		result["synced_roles"] = syncedRoles
		result["unsynced_roles"] = totalRoles - syncedRoles
	}

	// Step 5: Last periodic sync time.
	b.mu.RLock()
	lastSync := b.lastSync
	b.mu.RUnlock()

	if !lastSync.IsZero() {
		result["last_periodic_sync"] = lastSync.UTC().Format(time.RFC3339)
	} else {
		result["last_periodic_sync"] = ""
	}

	// Aggregate status.
	result["ok"] = result["configured"].(bool) &&
		result["vaultwarden_reachable"].(bool) &&
		result["authenticated"].(bool)

	return &logical.Response{Data: result}, nil
}

// checkVaultwardenAlive performs a simple HTTP GET to /alive with a short timeout.
// This endpoint does not require authentication.
func checkVaultwardenAlive(baseURL string) (bool, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(baseURL + "/alive")
	if err != nil {
		return false, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return true, nil
}
