// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Sync path handlers for the Vaultwarden secrets engine.
//
// The sync operation:
//  1. Reads the role definition
//  2. Reads the source secret from OpenBao KV using the configured bao_token
//     (the caller's token is only a fallback when no bao_token is set)
//  3. Encrypts all cipher fields using Bitwarden client-side encryption
//  4. Creates or updates the cipher in Vaultwarden
//  5. Saves the cipher ID back to the role for future updates

package vaultwarden

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathSync returns the path configurations for sync endpoints.
func pathSync(b *vaultwardenBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "sync/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "The name of the role to sync.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathSyncStatus,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "read-sync-status",
						OperationSuffix: "named",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathSyncRole,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "sync-role",
						OperationSuffix: "named",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathSyncDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "delete-synced-cipher",
						OperationSuffix: "named",
					},
				},
			},
			HelpSynopsis:    "Read sync status, sync, or delete a role's cipher in Vaultwarden.",
			HelpDescription: "GET: Returns the sync status of a role. POST: Reads the source secret from OpenBao KV, encrypts it, and pushes it to Vaultwarden. DELETE: Removes the cipher from Vaultwarden (role is preserved).",
		},
		{
			Pattern: "sync/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
				Navigation:      true,
				ItemType:        "Sync",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathSyncList,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "list-sync",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathSyncAll,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "sync-all",
					},
				},
			},
			HelpSynopsis:    "List sync status or sync all roles to Vaultwarden.",
			HelpDescription: "LIST: Shows all roles with their sync state (cipher_id, synced_at). POST: Syncs all roles to Vaultwarden.",
		},
	}
}

// pathSyncRole syncs a single role's secret to Vaultwarden.
func (b *vaultwardenBackend) pathSyncRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.readRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", name), nil
	}

	result, err := b.syncSingleRole(ctx, req, role)
	if err != nil {
		// Reset cached client so next attempt re-authenticates to Vaultwarden.
		b.resetClient()
		return nil, fmt.Errorf("syncing role %q: %w", name, err)
	}

	return &logical.Response{
		Data: result,
	}, nil
}

// pathSyncStatus returns the sync status of a single role.
// If the role has a synced cipher, it also fetches the revision date from Vaultwarden.
func (b *vaultwardenBackend) pathSyncStatus(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.readRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", name), nil
	}

	data := map[string]interface{}{
		"role":        role.Name,
		"cipher_name": role.CipherName,
		"cipher_type": role.CipherType,
		"source_path": role.SourcePath,
		"cipher_id":   role.CipherID,
		"synced":      role.CipherID != "",
		"synced_at":   role.SyncedAt,
	}

	// If synced, try to get the revision date from Vaultwarden.
	if role.CipherID != "" {
		client, err := b.getClient(ctx, req.Storage)
		if err == nil {
			cipher, err := client.GetCipher(role.CipherID)
			if err == nil && cipher != nil {
				data["revision_date"] = cipher.RevisionDate
			} else if err != nil {
				data["vaultwarden_error"] = err.Error()
			}
		}
	}

	return &logical.Response{Data: data}, nil
}

// pathSyncDelete removes the Vaultwarden cipher associated with a role
// but preserves the role definition. The cipher_id is cleared on the role.
func (b *vaultwardenBackend) pathSyncDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.readRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", name), nil
	}

	if role.CipherID == "" {
		return logical.ErrorResponse("role %q has no synced cipher", name), nil
	}

	deletedID := role.CipherID
	if err := b.deleteCipherForRole(ctx, req.Storage, role); err != nil {
		b.resetClient()
		return nil, fmt.Errorf("deleting cipher for role %q: %w", name, err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"deleted_cipher_id": deletedID,
			"role":              name,
		},
	}, nil
}

// pathSyncList lists all roles with their sync state.
func (b *vaultwardenBackend) pathSyncList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	if len(entries) == 0 {
		return logical.ListResponse(nil), nil
	}

	keyInfo := make(map[string]interface{}, len(entries))
	for _, name := range entries {
		role, err := b.readRole(ctx, req.Storage, name)
		if err != nil {
			keyInfo[name] = map[string]interface{}{
				"error": fmt.Sprintf("failed to read: %v", err),
			}
			continue
		}
		keyInfo[name] = map[string]interface{}{
			"cipher_name": role.CipherName,
			"cipher_id":   role.CipherID,
			"synced":      role.CipherID != "",
			"synced_at":   role.SyncedAt,
			"source_path": role.SourcePath,
		}
	}

	return logical.ListResponseWithInfo(entries, keyInfo), nil
}

// pathSyncAll syncs all defined roles to Vaultwarden.
func (b *vaultwardenBackend) pathSyncAll(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	if len(entries) == 0 {
		return logical.ErrorResponse("no roles defined"), nil
	}

	results := make(map[string]interface{})
	var synced, failed int

	for _, name := range entries {
		role, err := b.readRole(ctx, req.Storage, name)
		if err != nil {
			results[name] = map[string]interface{}{
				"status": "error",
				"error":  fmt.Sprintf("reading role: %v", err),
			}
			failed++
			continue
		}

		result, err := b.syncSingleRole(ctx, req, role)
		if err != nil {
			// Reset cached client so subsequent roles retry with a fresh connection.
			b.resetClient()
			results[name] = map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
			}
			failed++
			continue
		}

		result["status"] = "synced"
		results[name] = result
		synced++
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"total":   len(entries),
			"synced":  synced,
			"failed":  failed,
			"results": results,
		},
	}, nil
}

// syncSingleRole performs the actual sync for a single role.
func (b *vaultwardenBackend) syncSingleRole(ctx context.Context, req *logical.Request, role *roleEntry) (map[string]interface{}, error) {
	// Get the Vaultwarden client.
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("getting client: %w", err)
	}

	// Read the plugin config for org ID.
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	// Read the source secret from OpenBao KV using the configured bao_token
	// (falling back to the caller's token when none is configured).
	secretData, err := b.readSourceSecret(ctx, req, role.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("reading source secret at %q: %w", role.SourcePath, err)
	}

	// Determine which encryption keys to use.
	var encKey, macKey []byte
	orgID := config.OrganizationID
	if orgID != "" {
		encKey, macKey, err = client.GetOrgEncryptionKeys(orgID)
		if err != nil {
			return nil, fmt.Errorf("getting org encryption keys: %w", err)
		}
	} else {
		encKey, macKey = client.GetEncryptionKeys()
	}

	// Build the cipher request with encrypted fields.
	cipherReq, err := b.buildCipherRequest(role, secretData, orgID, encKey, macKey)
	if err != nil {
		return nil, fmt.Errorf("building cipher request: %w", err)
	}

	// If we don't have a cipher ID, look for existing ciphers by name.
	// This handles recovery from a previous sync that created the cipher but
	// failed to persist the cipher ID back to the role.
	// Also deduplicates: if multiple ciphers share the same name, keep the
	// newest (by RevisionDate) and delete the rest.
	if role.CipherID == "" {
		matches, findErr := client.FindAllCiphersByName(role.CipherName, orgID)
		if findErr != nil {
			b.logger.Warn("FindAllCiphersByName failed, will create new", "role", role.Name, "error", findErr)
		} else if len(matches) > 0 {
			// Pick the newest cipher by RevisionDate.
			best := matches[0]
			for _, m := range matches[1:] {
				if m.RevisionDate > best.RevisionDate {
					best = m
				}
			}
			role.CipherID = best.ID
			b.logger.Info("found existing cipher by name, will update", "role", role.Name, "cipher_id", best.ID, "total_matches", len(matches))

			// Delete duplicates (all except the one we're keeping).
			if len(matches) > 1 {
				b.logger.Info("deduplicating ciphers", "role", role.Name, "duplicates", len(matches)-1)
				for _, dup := range matches {
					if dup.ID == best.ID {
						continue
					}
					b.logger.Info("deleting duplicate cipher", "role", role.Name, "cipher_id", dup.ID)
					if orgID != "" {
						err = client.DeleteOrgCipher(dup.ID)
					} else {
						err = client.DeleteCipher(dup.ID)
					}
					if err != nil {
						b.logger.Warn("failed to delete duplicate cipher", "role", role.Name, "cipher_id", dup.ID, "error", err)
					}
				}
			}
		}
	}

	// Create or update the cipher.
	var cipherResp *CipherResponse
	if role.CipherID != "" {
		// Update existing cipher. Org ciphers have no user_uuid, so the standard
		// PUT /api/ciphers/<id> endpoint can't match ownership — use the admin
		// endpoint which checks org membership instead.
		b.logger.Info("updating cipher", "role", role.Name, "cipher_id", role.CipherID)
		if orgID != "" {
			cipherResp, err = client.UpdateOrgCipher(role.CipherID, cipherReq)
		} else {
			cipherResp, err = client.UpdateCipher(role.CipherID, cipherReq)
		}
		if err != nil {
			// If update fails (e.g., cipher was deleted), try creating a new one.
			b.logger.Warn("update failed, trying create", "role", role.Name, "error", err)
			role.CipherID = ""
		}
	}

	if role.CipherID == "" {
		// Create new cipher.
		b.logger.Info("creating cipher", "role", role.Name, "cipher_name", role.CipherName)
		if orgID != "" {
			cipherResp, err = client.CreateOrgCipher(cipherReq, role.CollectionIDs)
		} else {
			cipherResp, err = client.CreateCipher(cipherReq)
		}
		if err != nil {
			return nil, fmt.Errorf("creating cipher: %w", err)
		}
	}

	// Save the cipher ID and sync timestamp back to the role — this is a hard error.
	// If we can't persist the ID, we fail the sync so the operator is aware.
	// On retry, FindCipherByName above will recover the existing cipher.
	role.CipherID = cipherResp.ID
	role.SyncedAt = time.Now().UTC().Format(time.RFC3339)
	if err := b.writeRole(ctx, req.Storage, role); err != nil {
		return nil, fmt.Errorf("cipher %s created/updated but failed to save ID to role %q (will recover on retry): %w",
			cipherResp.ID, role.Name, err)
	}

	return map[string]interface{}{
		"cipher_id":   cipherResp.ID,
		"cipher_name": role.CipherName,
		"synced_at":   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// readSourceSecret reads a secret from an OpenBao KV mount through the HTTP
// API at the configured bao_addr. It authenticates with the configured
// bao_token, falling back to the caller's token when none is set.
func (b *vaultwardenBackend) readSourceSecret(ctx context.Context, req *logical.Request, path string) (map[string]interface{}, error) {
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	// External plugins receive a wrapped client token that lacks cross-mount access.
	// Use the configured bao_token which has the actual permissions needed.
	var token string
	if config != nil && config.BaoToken != "" {
		token = config.BaoToken
	} else {
		token = req.ClientToken
	}
	if token == "" {
		return nil, fmt.Errorf("no token available: set bao_token in config")
	}

	// Use the configured bao_addr explicitly — plugin subprocesses don't inherit env vars.
	addr := "http://127.0.0.1:8200"
	if config != nil && config.BaoAddr != "" {
		addr = config.BaoAddr
	}
	baoConfig := &api.Config{Address: addr}
	// TLS certificates are verified by default. Verification is only disabled
	// when the operator has explicitly set bao_tls_skip_verify in the config.
	if config != nil && config.BaoTLSSkipVerify {
		if err := baoConfig.ConfigureTLS(&api.TLSConfig{Insecure: true}); err != nil {
			return nil, fmt.Errorf("configuring OpenBao TLS: %w", err)
		}
	}

	baoClient, err := api.NewClient(baoConfig)
	if err != nil {
		return nil, fmt.Errorf("creating OpenBao client: %w", err)
	}
	baoClient.SetToken(token)

	secret, err := baoClient.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("reading from %q: %w", path, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found at %q", path)
	}

	// For KV v2, the data is nested under "data".
	if data, ok := secret.Data["data"].(map[string]interface{}); ok {
		return data, nil
	}

	// For KV v1, the data is at the top level.
	return secret.Data, nil
}

// buildCipherRequest builds an encrypted CipherRequest from a role and secret data.
func (b *vaultwardenBackend) buildCipherRequest(role *roleEntry, secretData map[string]interface{}, orgID string, encKey, macKey []byte) (*CipherRequest, error) {
	// Encrypt the cipher name.
	encryptedName, err := EncryptCipherString(role.CipherName, encKey, macKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting cipher name: %w", err)
	}

	cipher := &CipherRequest{
		Type:           role.CipherType,
		Name:           encryptedName,
		OrganizationID: orgID,
		CollectionIDs:  role.CollectionIDs,
		FolderID:       role.FolderID,
	}

	// Encrypt notes if provided.
	if role.NotesTemplate != "" {
		encryptedNotes, err := EncryptCipherString(role.NotesTemplate, encKey, macKey)
		if err != nil {
			return nil, fmt.Errorf("encrypting notes: %w", err)
		}
		cipher.Notes = encryptedNotes
	}

	// Track which source fields are mapped to structured cipher fields
	// so they aren't duplicated as custom fields.
	knownFields := map[string]bool{}

	switch role.CipherType {
	case cipherTypeLogin:
		cipher.Login, err = b.buildLoginData(role, secretData, encKey, macKey, knownFields)
		if err != nil {
			return nil, err
		}

	case cipherTypeSecureNote:
		cipher.SecureNote = &CipherSecureNoteData{Type: 0}
		// Secure notes have no structured fields beyond name/notes.

	case cipherTypeCard:
		cipher.Card, err = b.buildCardData(role, secretData, encKey, macKey, knownFields)
		if err != nil {
			return nil, err
		}

	case cipherTypeIdentity:
		cipher.Identity, err = b.buildIdentityData(role, secretData, encKey, macKey, knownFields)
		if err != nil {
			return nil, err
		}
	}

	// Add remaining fields as custom fields.
	var fields []CipherFieldData
	for key, val := range secretData {
		if knownFields[key] {
			continue
		}

		encName, err := EncryptCipherString(key, encKey, macKey)
		if err != nil {
			return nil, fmt.Errorf("encrypting field name %q: %w", key, err)
		}

		encVal, err := EncryptCipherString(fmt.Sprintf("%v", val), encKey, macKey)
		if err != nil {
			return nil, fmt.Errorf("encrypting field value %q: %w", key, err)
		}

		fields = append(fields, CipherFieldData{
			Name:  encName,
			Value: encVal,
			Type:  0, // text
		})
	}

	if len(fields) > 0 {
		cipher.Fields = fields
	}

	return cipher, nil
}

// encryptField encrypts a field value from secretData if the mapping exists.
// Returns the encrypted value, or empty string if the field is not mapped.
// Marks the field as known to prevent duplicate custom fields.
func (b *vaultwardenBackend) encryptField(fieldName string, secretData map[string]interface{}, encKey, macKey []byte, knownFields map[string]bool) (string, error) {
	if fieldName == "" {
		return "", nil
	}
	knownFields[fieldName] = true
	val, ok := secretData[fieldName]
	if !ok {
		return "", nil
	}
	enc, err := EncryptCipherString(fmt.Sprintf("%v", val), encKey, macKey)
	if err != nil {
		return "", fmt.Errorf("encrypting %q: %w", fieldName, err)
	}
	return enc, nil
}

// buildLoginData builds encrypted login cipher data.
func (b *vaultwardenBackend) buildLoginData(role *roleEntry, secretData map[string]interface{}, encKey, macKey []byte, knownFields map[string]bool) (*CipherLoginData, error) {
	loginData := &CipherLoginData{}

	username, err := b.encryptField(role.UserField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	loginData.Username = username

	password, err := b.encryptField(role.PassField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	loginData.Password = password

	uri, err := b.encryptField(role.URLField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	if uri != "" {
		loginData.URIs = []CipherURI{{URI: uri, Match: nil}}
	}

	// Append extra static URIs (subdomain aliases, etc.).
	for _, extraURL := range role.ExtraURLs {
		encExtra, err := EncryptCipherString(extraURL, encKey, macKey)
		if err != nil {
			return nil, fmt.Errorf("encrypting extra URL %q: %w", extraURL, err)
		}
		loginData.URIs = append(loginData.URIs, CipherURI{URI: encExtra, Match: nil})
	}

	return loginData, nil
}

// buildCardData builds encrypted card cipher data.
func (b *vaultwardenBackend) buildCardData(role *roleEntry, secretData map[string]interface{}, encKey, macKey []byte, knownFields map[string]bool) (*CipherCardData, error) {
	card := &CipherCardData{}
	var err error

	card.CardholderName, err = b.encryptField(role.CardholderNameField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	card.Brand, err = b.encryptField(role.BrandField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	card.Number, err = b.encryptField(role.NumberField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	card.ExpMonth, err = b.encryptField(role.ExpMonthField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	card.ExpYear, err = b.encryptField(role.ExpYearField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	card.Code, err = b.encryptField(role.CodeField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}

	return card, nil
}

// buildIdentityData builds encrypted identity cipher data.
func (b *vaultwardenBackend) buildIdentityData(role *roleEntry, secretData map[string]interface{}, encKey, macKey []byte, knownFields map[string]bool) (*CipherIdentityData, error) {
	id := &CipherIdentityData{}
	var err error

	id.Title, err = b.encryptField(role.TitleField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.FirstName, err = b.encryptField(role.FirstNameField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.MiddleName, err = b.encryptField(role.MiddleNameField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.LastName, err = b.encryptField(role.LastNameField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.Email, err = b.encryptField(role.EmailField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.Phone, err = b.encryptField(role.PhoneField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.Company, err = b.encryptField(role.CompanyField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.SSN, err = b.encryptField(role.SSNField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.Username, err = b.encryptField(role.IdentityUserField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.PassportNumber, err = b.encryptField(role.PassportNumberField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.LicenseNumber, err = b.encryptField(role.LicenseNumberField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.Address1, err = b.encryptField(role.Address1Field, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.Address2, err = b.encryptField(role.Address2Field, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.Address3, err = b.encryptField(role.Address3Field, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.City, err = b.encryptField(role.CityField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.State, err = b.encryptField(role.StateField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.PostalCode, err = b.encryptField(role.PostalCodeField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}
	id.Country, err = b.encryptField(role.CountryField, secretData, encKey, macKey, knownFields)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// deleteCipherForRole deletes the Vaultwarden cipher associated with a role
// and clears the cipher_id on the role. Errors from cipher deletion are returned;
// the caller decides whether to treat them as fatal.
func (b *vaultwardenBackend) deleteCipherForRole(ctx context.Context, s logical.Storage, role *roleEntry) error {
	if role.CipherID == "" {
		return nil
	}

	client, err := b.getClient(ctx, s)
	if err != nil {
		return fmt.Errorf("getting client: %w", err)
	}

	config, err := b.readConfig(ctx, s)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	b.logger.Info("deleting cipher", "role", role.Name, "cipher_id", role.CipherID)

	if config != nil && config.OrganizationID != "" {
		err = client.DeleteOrgCipher(role.CipherID)
	} else {
		err = client.DeleteCipher(role.CipherID)
	}
	if err != nil {
		return fmt.Errorf("deleting cipher %s: %w", role.CipherID, err)
	}

	// Clear the cipher ID and persist.
	role.CipherID = ""
	if writeErr := b.writeRole(ctx, s, role); writeErr != nil {
		b.logger.Warn("cipher deleted but failed to clear cipher_id on role", "role", role.Name, "error", writeErr)
	}

	return nil
}
