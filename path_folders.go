// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Folder path handlers for the Vaultwarden secrets engine.

package vaultwarden

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathFolders returns the path configurations for folders/ endpoints.
func pathFolders(b *vaultwardenBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "folders/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
				Navigation:      true,
				ItemType:        "Folder",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathFoldersList,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "list-folders",
					},
				},
			},
			HelpSynopsis:    "List Vaultwarden folders.",
			HelpDescription: "Lists all folders with decrypted names.",
		},
		{
			Pattern: "folders/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The folder name (will be encrypted before sending to Vaultwarden).",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathFolderCreate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "create-folder",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathFolderCreate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "create-folder",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathFolderDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "delete-folder",
					},
				},
			},
			HelpSynopsis:    "Create or delete a Vaultwarden folder.",
			HelpDescription: "Creates a folder with the given name, or deletes a folder by its ID passed as the name parameter.",
		},
	}
}

// pathFoldersList lists all Vaultwarden folders with decrypted names.
func (b *vaultwardenBackend) pathFoldersList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	folders, err := client.ListFolders()
	if err != nil {
		b.resetClient()
		return nil, fmt.Errorf("listing folders: %w", err)
	}

	// Decrypt folder names using user's symmetric key.
	encKey, macKey := client.GetEncryptionKeys()

	items := make([]map[string]interface{}, 0, len(folders))
	for _, f := range folders {
		name := f.Name
		if decrypted, err := DecryptCipherString(f.Name, encKey, macKey); err == nil {
			name = decrypted
		}

		items = append(items, map[string]interface{}{
			"id":   f.ID,
			"name": name,
		})
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"folders": items,
			"total":   len(items),
		},
	}, nil
}

// pathFolderCreate creates a new Vaultwarden folder.
func (b *vaultwardenBackend) pathFolderCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Folders are encrypted with the user's personal key (not org key).
	encKey, macKey := client.GetEncryptionKeys()
	encryptedName, err := EncryptCipherString(name, encKey, macKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting folder name: %w", err)
	}

	folder, err := client.CreateFolder(encryptedName)
	if err != nil {
		b.resetClient()
		return nil, fmt.Errorf("creating folder: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"id":   folder.ID,
			"name": name,
		},
	}, nil
}

// pathFolderDelete deletes a Vaultwarden folder by ID.
// The "name" parameter is used as the folder ID for deletion.
func (b *vaultwardenBackend) pathFolderDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	folderID := d.Get("name").(string)

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if err := client.DeleteFolder(folderID); err != nil {
		b.resetClient()
		return nil, fmt.Errorf("deleting folder: %w", err)
	}

	return nil, nil
}
