// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Package vaultwarden implements an OpenBao secrets engine plugin that syncs
// secrets to Vaultwarden (Bitwarden-compatible) instances.
//
// The plugin provides:
//   - Configuration management for Vaultwarden connectivity
//   - Role definitions mapping OpenBao KV paths to Vaultwarden ciphers
//   - Sync operations that read secrets from OpenBao KV, encrypt them with
//     Bitwarden client-side encryption, and push to Vaultwarden
package vaultwarden

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// backendHelp is the help string for the backend.
	backendHelp = `
The Vaultwarden secrets engine syncs secrets from OpenBao KV to a
Vaultwarden (Bitwarden-compatible) instance.

Secrets are encrypted client-side using Bitwarden's encryption scheme
(PBKDF2 + HKDF + AES-256-CBC + HMAC-SHA256) before being pushed to
the Vaultwarden API as cipher items in an organization.

Configure the plugin with the Vaultwarden URL, email, master password,
and organization ID. Then define roles that map OpenBao KV paths to
Vaultwarden ciphers. Use the sync endpoint to push secrets.

IMPORTANT: The Vaultwarden service account used by this plugin must use
PBKDF2 as its KDF type. Argon2id is not supported. Set the account's
KDF to "PBKDF2 SHA-256" in Vaultwarden Settings > Security > Keys.
`
)

// vaultwardenBackend is the OpenBao secrets engine backend.
type vaultwardenBackend struct {
	*framework.Backend

	client     *VaultwardenClient
	mu         sync.RWMutex
	logger     hclog.Logger
	lastSync   time.Time           // last periodic sync time
	dataHashes map[string][32]byte // role name -> SHA-256 of last synced KV data
}

// Factory creates a new backend instance. This is the entry point called by
// OpenBao when the plugin is loaded.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend(conf.Logger)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, fmt.Errorf("setup failed: %w", err)
	}
	return b, nil
}

// newBackend creates the backend with all path definitions.
func newBackend(logger hclog.Logger) *vaultwardenBackend {
	b := &vaultwardenBackend{
		logger:     logger,
		dataHashes: make(map[string][32]byte),
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			pathConfig(b),
			pathStatus(b),
			pathRoles(b),
			pathSync(b),
			pathCollections(b),
			pathFolders(b),
		),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Invalidate:   b.invalidate,
		PeriodicFunc: b.periodicSync,
	}

	return b
}

// invalidate is called when a key is modified in storage. If the config
// changes, we invalidate the cached client.
func (b *vaultwardenBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.mu.Lock()
		b.client = nil
		b.mu.Unlock()
		b.logger.Info("config invalidated, client will be re-created on next use")
	}
}

// getClient returns a cached or newly created VaultwardenClient.
// It reads the plugin config from storage and creates a client if needed.
func (b *vaultwardenBackend) getClient(ctx context.Context, s logical.Storage) (*VaultwardenClient, error) {
	b.mu.RLock()
	if b.client != nil {
		client := b.client
		b.mu.RUnlock()
		return client, nil
	}
	b.mu.RUnlock()

	// Need to create a new client.
	b.mu.Lock()
	defer b.mu.Unlock()

	// Double-check after acquiring write lock.
	if b.client != nil {
		return b.client, nil
	}

	config, err := b.readConfig(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	if config == nil {
		return nil, fmt.Errorf("plugin not configured: write to config/ first")
	}

	client, err := NewClient(&VaultwardenConfig{
		URL:            config.URL,
		Email:          config.Email,
		Password:       config.Password,
		OrganizationID: config.OrganizationID,
	}, b.logger)
	if err != nil {
		return nil, fmt.Errorf("creating Vaultwarden client: %w", err)
	}

	b.client = client
	return client, nil
}

// readConfig reads the plugin configuration from storage.
func (b *vaultwardenBackend) readConfig(ctx context.Context, s logical.Storage) (*pluginConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, fmt.Errorf("reading config from storage: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var config pluginConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}

	return &config, nil
}

// resetClient clears the cached client, forcing re-creation on next use.
func (b *vaultwardenBackend) resetClient() {
	b.mu.Lock()
	b.client = nil
	b.mu.Unlock()
}

// periodicSync is called by OpenBao's rollback manager on a regular interval.
// It auto-syncs all roles if sync_interval is configured and enough time has passed.
// Roles whose KV data hasn't changed since the last sync are skipped.
func (b *vaultwardenBackend) periodicSync(ctx context.Context, req *logical.Request) error {
	// Errors below are logged and swallowed on purpose: returning an error
	// from the periodic function would only make OpenBao log it again, and
	// the next tick retries anyway.
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		b.logger.Warn("periodic sync: failed to read config, skipping this run", "error", err)
		return nil
	}
	if config == nil {
		return nil // not configured — no-op
	}

	if config.SyncInterval == "" {
		return nil // periodic sync disabled
	}

	interval, err := time.ParseDuration(config.SyncInterval)
	if err != nil {
		b.logger.Warn("periodic sync: invalid sync_interval, periodic sync is disabled", "sync_interval", config.SyncInterval, "error", err)
		return nil
	}
	if interval <= 0 {
		return nil // zero or negative interval — disabled
	}

	b.mu.RLock()
	lastSync := b.lastSync
	b.mu.RUnlock()

	if time.Since(lastSync) < interval {
		return nil // not yet time
	}

	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		b.logger.Warn("periodic sync: failed to list roles, skipping this run", "error", err)
		return nil
	}
	if len(entries) == 0 {
		return nil
	}

	var synced, skipped, failed int
	for _, name := range entries {
		role, err := b.readRole(ctx, req.Storage, name)
		if err != nil {
			b.logger.Error("periodic sync: failed to read role", "role", name, "error", err)
			failed++
			continue
		}

		// Read source data to compute hash for change detection.
		secretData, err := b.readSourceSecret(ctx, req, role.SourcePath)
		if err != nil {
			b.logger.Error("periodic sync: failed to read source secret", "role", name, "error", err)
			failed++
			continue
		}

		hash := computeDataHash(secretData)

		b.mu.RLock()
		lastHash, hasHash := b.dataHashes[name]
		b.mu.RUnlock()

		if hasHash && hash == lastHash {
			skipped++
			continue // data hasn't changed
		}

		// Data changed (or first sync) — perform sync.
		if _, err := b.syncSingleRole(ctx, req, role); err != nil {
			b.resetClient()
			b.logger.Error("periodic sync: failed", "role", name, "error", err)
			failed++
			continue
		}

		b.mu.Lock()
		b.dataHashes[name] = hash
		b.mu.Unlock()
		synced++
	}

	b.mu.Lock()
	b.lastSync = time.Now()
	b.mu.Unlock()

	if synced > 0 || failed > 0 {
		b.logger.Info("periodic sync completed", "synced", synced, "skipped", skipped, "failed", failed)
	}

	return nil
}

// computeDataHash computes a deterministic SHA-256 hash of secret data.
// Used for change detection in periodic sync.
func computeDataHash(data map[string]interface{}) [32]byte {
	// Sort keys for deterministic ordering.
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte("="))
		h.Write([]byte(fmt.Sprintf("%v", data[k])))
		h.Write([]byte("\n"))
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
