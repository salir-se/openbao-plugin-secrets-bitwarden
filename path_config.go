// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Configuration path handlers for the Vaultwarden secrets engine.

package vaultwarden

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pluginConfig holds the Vaultwarden connection configuration.
type pluginConfig struct {
	URL            string `json:"url"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	OrganizationID string `json:"organization_id"`
	BaoToken       string `json:"bao_token"`
	BaoAddr        string `json:"bao_addr"`
	SyncInterval   string `json:"sync_interval"`

	// BaoTLSSkipVerify disables TLS certificate verification for requests to
	// OpenBao (bao_addr). Configs stored before this field existed decode to false.
	BaoTLSSkipVerify bool `json:"bao_tls_skip_verify"`
}

// pathConfig returns the path configuration for the config/ endpoint.
func pathConfig(b *vaultwardenBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
				Navigation:      true,
				ItemType:        "Configuration",
			},
			Fields: map[string]*framework.FieldSchema{
				"url": {
					Type:        framework.TypeString,
					Description: "The URL of the Vaultwarden instance (e.g., https://vault.example.com).",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "URL",
					},
				},
				"email": {
					Type:        framework.TypeString,
					Description: "The email address used to authenticate with Vaultwarden.",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "The master password for the Vaultwarden account. The account must use PBKDF2 (not Argon2id) as its KDF type.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"organization_id": {
					Type:        framework.TypeString,
					Description: "The Vaultwarden organization ID for cipher operations.",
				},
				"bao_token": {
					Type:        framework.TypeString,
					Description: "OpenBao token for reading source secrets from KV mounts.",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"bao_addr": {
					Type:        framework.TypeString,
					Description: "OpenBao API address (e.g., http://127.0.0.1:8200). Defaults to http://127.0.0.1:8200.",
					Default:     "http://127.0.0.1:8200",
				},
				"bao_tls_skip_verify": {
					Type:        framework.TypeBool,
					Description: "Disable TLS certificate verification when reading source secrets from OpenBao (bao_addr). Insecure; only for development or when bao_addr uses a certificate that cannot be verified. Defaults to false.",
					Default:     false,
				},
				"sync_interval": {
					Type:        framework.TypeString,
					Description: "Periodic sync interval as a Go duration (e.g., '10m', '1h'). Empty or '0' disables periodic sync. Changed KV data is detected automatically — unchanged roles are skipped.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "configure",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "configure",
					},
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "read-configuration",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "delete-configuration",
					},
				},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    "Configure the Vaultwarden connection.",
			HelpDescription: "Configure the URL, credentials, and organization for the Vaultwarden secrets engine.",
		},
	}
}

// pathConfigExistenceCheck checks if the config already exists.
func (b *vaultwardenBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return false, fmt.Errorf("checking config existence: %w", err)
	}
	return entry != nil, nil
}

// pathConfigRead reads the current configuration, masking the password.
func (b *vaultwardenBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"url":                 config.URL,
			"email":               config.Email,
			"organization_id":     config.OrganizationID,
			"bao_addr":            config.BaoAddr,
			"bao_tls_skip_verify": config.BaoTLSSkipVerify,
			"sync_interval":       config.SyncInterval,
			// password and bao_token are intentionally omitted — sensitive
		},
	}, nil
}

// pathConfigWrite creates or updates the configuration.
func (b *vaultwardenBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = &pluginConfig{}
	}

	// Update fields if provided.
	if v, ok := d.GetOk("url"); ok {
		config.URL = v.(string)
	}
	if v, ok := d.GetOk("email"); ok {
		config.Email = v.(string)
	}
	if v, ok := d.GetOk("password"); ok {
		config.Password = v.(string)
	}
	if v, ok := d.GetOk("organization_id"); ok {
		config.OrganizationID = v.(string)
	}
	if v, ok := d.GetOk("bao_token"); ok {
		config.BaoToken = v.(string)
	}
	if v, ok := d.GetOk("bao_addr"); ok {
		config.BaoAddr = v.(string)
	}
	if v, ok := d.GetOk("bao_tls_skip_verify"); ok {
		config.BaoTLSSkipVerify = v.(bool)
	}
	if v, ok := d.GetOk("sync_interval"); ok {
		config.SyncInterval = v.(string)
	}

	// Validate required fields.
	if config.URL == "" {
		return logical.ErrorResponse("url is required"), nil
	}
	if config.Email == "" {
		return logical.ErrorResponse("email is required"), nil
	}
	if config.Password == "" {
		return logical.ErrorResponse("password is required"), nil
	}

	// Store the configuration.
	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, fmt.Errorf("creating storage entry: %w", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("storing config: %w", err)
	}

	// Invalidate the cached client so it reconnects with new config.
	b.resetClient()

	return nil, nil
}

// pathConfigDelete deletes the configuration.
func (b *vaultwardenBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, fmt.Errorf("deleting config: %w", err)
	}

	b.resetClient()

	return nil, nil
}
