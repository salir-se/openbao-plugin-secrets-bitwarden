// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Collection path handlers for the Vaultwarden secrets engine.

package vaultwarden

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathCollections returns the path configurations for collections/ endpoints.
func pathCollections(b *vaultwardenBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "collections/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
				Navigation:      true,
				ItemType:        "Collection",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathCollectionsList,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "list-collections",
					},
				},
			},
			HelpSynopsis:    "List organization collections.",
			HelpDescription: "Lists all collections in the configured organization with decrypted names.",
		},
		{
			Pattern: "collections/" + framework.GenericNameRegex("cipher_name") + "/assign",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
			},
			Fields: map[string]*framework.FieldSchema{
				"cipher_name": {
					Type:        framework.TypeString,
					Description: "The role name whose cipher to update.",
					Required:    true,
				},
				"collection_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Collection IDs to assign the cipher to.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathCollectionsAssign,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "assign-collections",
					},
				},
			},
			HelpSynopsis:    "Assign a cipher to collections.",
			HelpDescription: "Updates the collection assignments for a role's cipher in Vaultwarden.",
		},
	}
}

// pathCollectionsList lists all collections in the configured organization.
func (b *vaultwardenBackend) pathCollectionsList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config.OrganizationID == "" {
		return logical.ErrorResponse("organization_id not configured"), nil
	}

	collections, err := client.ListOrgCollections(config.OrganizationID)
	if err != nil {
		b.resetClient()
		return nil, fmt.Errorf("listing collections: %w", err)
	}

	// Get org encryption keys for decrypting names.
	encKey, macKey, err := client.GetOrgEncryptionKeys(config.OrganizationID)
	if err != nil {
		return nil, fmt.Errorf("getting org encryption keys: %w", err)
	}

	items := make([]map[string]interface{}, 0, len(collections))
	for _, c := range collections {
		name := c.Name
		if decrypted, err := DecryptCipherString(c.Name, encKey, macKey); err == nil {
			name = decrypted
		}

		items = append(items, map[string]interface{}{
			"id":   c.ID,
			"name": name,
		})
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"collections": items,
			"total":       len(items),
		},
	}, nil
}

// pathCollectionsAssign updates the collection assignments for a role's cipher.
func (b *vaultwardenBackend) pathCollectionsAssign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("cipher_name").(string)
	collectionIDs := d.Get("collection_ids").([]string)

	role, err := b.readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}
	if role.CipherID == "" {
		return logical.ErrorResponse("role %q has no synced cipher — sync first", roleName), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	admin := config != nil && config.OrganizationID != ""
	if err := client.UpdateCipherCollections(role.CipherID, collectionIDs, admin); err != nil {
		b.resetClient()
		return nil, fmt.Errorf("updating collections: %w", err)
	}

	// Update the role's collection_ids to match.
	role.CollectionIDs = collectionIDs
	if err := b.writeRole(ctx, req.Storage, role); err != nil {
		b.logger.Warn("collections updated but failed to save to role", "role", roleName, "error", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"cipher_id":      role.CipherID,
			"collection_ids": collectionIDs,
		},
	}, nil
}
