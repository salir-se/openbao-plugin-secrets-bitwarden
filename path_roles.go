// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Role path handlers for the Vaultwarden secrets engine.
//
// Roles define the mapping between an OpenBao KV secret path and a Vaultwarden
// cipher. Each role specifies:
//   - source_path: the OpenBao KV path to read from (e.g., "secret/data/grafana")
//   - cipher_name: the display name in Vaultwarden
//   - field mappings: which source secret fields map to username, password, URI
//   - collection_ids: Vaultwarden collection assignments
//   - cipher_id: automatically set after first sync

package vaultwarden

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// Bitwarden cipher types.
	cipherTypeLogin      = 1
	cipherTypeSecureNote = 2
	cipherTypeCard       = 3
	cipherTypeIdentity   = 4
)

// roleEntry holds a role definition.
type roleEntry struct {
	Name          string   `json:"name"`
	SourcePath    string   `json:"source_path"`
	CollectionIDs []string `json:"collection_ids,omitempty"`
	FolderID      string   `json:"folder_id,omitempty"`
	CipherName    string   `json:"cipher_name"`
	CipherType    int      `json:"cipher_type"`
	NotesTemplate string   `json:"notes_template,omitempty"`
	CipherID      string   `json:"cipher_id,omitempty"`
	SyncedAt      string   `json:"synced_at,omitempty"`

	// Login fields (cipher_type=1).
	URLField  string   `json:"url_field,omitempty"`
	ExtraURLs []string `json:"extra_urls,omitempty"` // additional static URIs (e.g., subdomain aliases)
	UserField string   `json:"user_field,omitempty"`
	PassField string   `json:"pass_field,omitempty"`

	// Card fields (cipher_type=3).
	CardholderNameField string `json:"cardholder_name_field,omitempty"`
	BrandField          string `json:"brand_field,omitempty"`
	NumberField         string `json:"number_field,omitempty"`
	ExpMonthField       string `json:"exp_month_field,omitempty"`
	ExpYearField        string `json:"exp_year_field,omitempty"`
	CodeField           string `json:"code_field,omitempty"`

	// Identity fields (cipher_type=4).
	TitleField          string `json:"title_field,omitempty"`
	FirstNameField      string `json:"first_name_field,omitempty"`
	MiddleNameField     string `json:"middle_name_field,omitempty"`
	LastNameField       string `json:"last_name_field,omitempty"`
	EmailField          string `json:"email_field,omitempty"`
	PhoneField          string `json:"phone_field,omitempty"`
	CompanyField        string `json:"company_field,omitempty"`
	SSNField            string `json:"ssn_field,omitempty"`
	IdentityUserField   string `json:"identity_user_field,omitempty"`
	PassportNumberField string `json:"passport_number_field,omitempty"`
	LicenseNumberField  string `json:"license_number_field,omitempty"`
	Address1Field       string `json:"address1_field,omitempty"`
	Address2Field       string `json:"address2_field,omitempty"`
	Address3Field       string `json:"address3_field,omitempty"`
	CityField           string `json:"city_field,omitempty"`
	StateField          string `json:"state_field,omitempty"`
	PostalCodeField     string `json:"postal_code_field,omitempty"`
	CountryField        string `json:"country_field,omitempty"`
}

// pathRoles returns the path configurations for roles/ endpoints.
func pathRoles(b *vaultwardenBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
				OperationSuffix: "roles",
				Navigation:      true,
				ItemType:        "Role",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "list-roles",
					},
				},
			},
			HelpSynopsis:    "List all configured roles.",
			HelpDescription: "Returns a list of all role names that have been configured.",
		},
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "vaultwarden",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "The name of the role.",
					Required:    true,
				},
				"source_path": {
					Type:        framework.TypeString,
					Description: "The OpenBao KV path to read the source secret from (e.g., 'secret/data/grafana').",
					Required:    true,
				},
				"collection_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Vaultwarden collection IDs to assign the cipher to.",
				},
				"cipher_name": {
					Type:        framework.TypeString,
					Description: "The display name for the cipher in Vaultwarden.",
					Required:    true,
				},
				"cipher_type": {
					Type:        framework.TypeInt,
					Description: "The cipher type (1=login, 2=secure note, 3=card, 4=identity). Defaults to 1.",
					Default:     cipherTypeLogin,
				},
				"folder_id": {
					Type:        framework.TypeString,
					Description: "Vaultwarden folder ID to place the cipher in.",
				},
				"notes_template": {
					Type:        framework.TypeString,
					Description: "Static notes text to include in the cipher.",
				},
				// Login fields (cipher_type=1).
				"url_field": {
					Type:        framework.TypeString,
					Description: "Source field for primary URI (login type).",
				},
				"extra_urls": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Additional static URIs (e.g., subdomain aliases like 'https://alias.example.com'). These are added alongside the url_field value.",
				},
				"user_field": {
					Type:        framework.TypeString,
					Description: "Source field for username (login type).",
				},
				"pass_field": {
					Type:        framework.TypeString,
					Description: "Source field for password (login type).",
				},
				// Card fields (cipher_type=3).
				"cardholder_name_field": {
					Type:        framework.TypeString,
					Description: "Source field for cardholder name (card type).",
				},
				"brand_field": {
					Type:        framework.TypeString,
					Description: "Source field for card brand (card type).",
				},
				"number_field": {
					Type:        framework.TypeString,
					Description: "Source field for card number (card type).",
				},
				"exp_month_field": {
					Type:        framework.TypeString,
					Description: "Source field for expiry month (card type).",
				},
				"exp_year_field": {
					Type:        framework.TypeString,
					Description: "Source field for expiry year (card type).",
				},
				"code_field": {
					Type:        framework.TypeString,
					Description: "Source field for security code (card type).",
				},
				// Identity fields (cipher_type=4).
				"title_field": {
					Type:        framework.TypeString,
					Description: "Source field for title (identity type).",
				},
				"first_name_field": {
					Type:        framework.TypeString,
					Description: "Source field for first name (identity type).",
				},
				"middle_name_field": {
					Type:        framework.TypeString,
					Description: "Source field for middle name (identity type).",
				},
				"last_name_field": {
					Type:        framework.TypeString,
					Description: "Source field for last name (identity type).",
				},
				"email_field": {
					Type:        framework.TypeString,
					Description: "Source field for email (identity type).",
				},
				"phone_field": {
					Type:        framework.TypeString,
					Description: "Source field for phone (identity type).",
				},
				"company_field": {
					Type:        framework.TypeString,
					Description: "Source field for company (identity type).",
				},
				"ssn_field": {
					Type:        framework.TypeString,
					Description: "Source field for SSN (identity type).",
				},
				"identity_user_field": {
					Type:        framework.TypeString,
					Description: "Source field for username (identity type).",
				},
				"passport_number_field": {
					Type:        framework.TypeString,
					Description: "Source field for passport number (identity type).",
				},
				"license_number_field": {
					Type:        framework.TypeString,
					Description: "Source field for license number (identity type).",
				},
				"address1_field": {
					Type:        framework.TypeString,
					Description: "Source field for address line 1 (identity type).",
				},
				"address2_field": {
					Type:        framework.TypeString,
					Description: "Source field for address line 2 (identity type).",
				},
				"address3_field": {
					Type:        framework.TypeString,
					Description: "Source field for address line 3 (identity type).",
				},
				"city_field": {
					Type:        framework.TypeString,
					Description: "Source field for city (identity type).",
				},
				"state_field": {
					Type:        framework.TypeString,
					Description: "Source field for state (identity type).",
				},
				"postal_code_field": {
					Type:        framework.TypeString,
					Description: "Source field for postal code (identity type).",
				},
				"country_field": {
					Type:        framework.TypeString,
					Description: "Source field for country (identity type).",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "create-role",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "update-role",
					},
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "read-role",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "delete-role",
					},
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    "Manage a role that maps an OpenBao KV path to a Vaultwarden cipher.",
			HelpDescription: "Create, read, update, or delete a role. Roles define how OpenBao secrets are synced to Vaultwarden.",
		},
	}
}

// pathRoleExistenceCheck checks if a role exists in storage.
func (b *vaultwardenBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	entry, err := req.Storage.Get(ctx, "role/"+name)
	if err != nil {
		return false, fmt.Errorf("checking role existence: %w", err)
	}
	return entry != nil, nil
}

// pathRolesList lists all role names with sync metadata in key_info.
func (b *vaultwardenBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
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
			"cipher_type": role.CipherType,
			"source_path": role.SourcePath,
			"cipher_id":   role.CipherID,
			"synced":      role.CipherID != "",
			"synced_at":   role.SyncedAt,
		}
	}

	return logical.ListResponseWithInfo(entries, keyInfo), nil
}

// pathRoleRead reads a role definition.
func (b *vaultwardenBackend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.readRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"name":           role.Name,
		"source_path":    role.SourcePath,
		"collection_ids": role.CollectionIDs,
		"folder_id":      role.FolderID,
		"cipher_name":    role.CipherName,
		"cipher_type":    role.CipherType,
		"notes_template": role.NotesTemplate,
		"cipher_id":      role.CipherID,
		"synced_at":      role.SyncedAt,
	}

	// Include type-specific fields based on cipher type.
	switch role.CipherType {
	case cipherTypeLogin:
		data["url_field"] = role.URLField
		data["extra_urls"] = role.ExtraURLs
		data["user_field"] = role.UserField
		data["pass_field"] = role.PassField
	case cipherTypeCard:
		data["cardholder_name_field"] = role.CardholderNameField
		data["brand_field"] = role.BrandField
		data["number_field"] = role.NumberField
		data["exp_month_field"] = role.ExpMonthField
		data["exp_year_field"] = role.ExpYearField
		data["code_field"] = role.CodeField
	case cipherTypeIdentity:
		data["title_field"] = role.TitleField
		data["first_name_field"] = role.FirstNameField
		data["middle_name_field"] = role.MiddleNameField
		data["last_name_field"] = role.LastNameField
		data["email_field"] = role.EmailField
		data["phone_field"] = role.PhoneField
		data["company_field"] = role.CompanyField
		data["ssn_field"] = role.SSNField
		data["identity_user_field"] = role.IdentityUserField
		data["passport_number_field"] = role.PassportNumberField
		data["license_number_field"] = role.LicenseNumberField
		data["address1_field"] = role.Address1Field
		data["address2_field"] = role.Address2Field
		data["address3_field"] = role.Address3Field
		data["city_field"] = role.CityField
		data["state_field"] = role.StateField
		data["postal_code_field"] = role.PostalCodeField
		data["country_field"] = role.CountryField
	}
	// Secure note (type 2) has no type-specific fields.

	return &logical.Response{
		Data: data,
	}, nil
}

// pathRoleWrite creates or updates a role.
func (b *vaultwardenBackend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.readRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &roleEntry{
			Name:       name,
			CipherType: cipherTypeLogin,
		}
	}

	// Update fields if provided.
	if v, ok := d.GetOk("source_path"); ok {
		role.SourcePath = v.(string)
	}
	if v, ok := d.GetOk("collection_ids"); ok {
		role.CollectionIDs = v.([]string)
	}
	if v, ok := d.GetOk("folder_id"); ok {
		role.FolderID = v.(string)
	}
	if v, ok := d.GetOk("cipher_name"); ok {
		role.CipherName = v.(string)
	}
	if v, ok := d.GetOk("cipher_type"); ok {
		role.CipherType = v.(int)
	}
	if v, ok := d.GetOk("notes_template"); ok {
		role.NotesTemplate = v.(string)
	}
	// Login fields.
	if v, ok := d.GetOk("url_field"); ok {
		role.URLField = v.(string)
	}
	if v, ok := d.GetOk("extra_urls"); ok {
		role.ExtraURLs = v.([]string)
	}
	if v, ok := d.GetOk("user_field"); ok {
		role.UserField = v.(string)
	}
	if v, ok := d.GetOk("pass_field"); ok {
		role.PassField = v.(string)
	}
	// Card fields.
	if v, ok := d.GetOk("cardholder_name_field"); ok {
		role.CardholderNameField = v.(string)
	}
	if v, ok := d.GetOk("brand_field"); ok {
		role.BrandField = v.(string)
	}
	if v, ok := d.GetOk("number_field"); ok {
		role.NumberField = v.(string)
	}
	if v, ok := d.GetOk("exp_month_field"); ok {
		role.ExpMonthField = v.(string)
	}
	if v, ok := d.GetOk("exp_year_field"); ok {
		role.ExpYearField = v.(string)
	}
	if v, ok := d.GetOk("code_field"); ok {
		role.CodeField = v.(string)
	}
	// Identity fields.
	if v, ok := d.GetOk("title_field"); ok {
		role.TitleField = v.(string)
	}
	if v, ok := d.GetOk("first_name_field"); ok {
		role.FirstNameField = v.(string)
	}
	if v, ok := d.GetOk("middle_name_field"); ok {
		role.MiddleNameField = v.(string)
	}
	if v, ok := d.GetOk("last_name_field"); ok {
		role.LastNameField = v.(string)
	}
	if v, ok := d.GetOk("email_field"); ok {
		role.EmailField = v.(string)
	}
	if v, ok := d.GetOk("phone_field"); ok {
		role.PhoneField = v.(string)
	}
	if v, ok := d.GetOk("company_field"); ok {
		role.CompanyField = v.(string)
	}
	if v, ok := d.GetOk("ssn_field"); ok {
		role.SSNField = v.(string)
	}
	if v, ok := d.GetOk("identity_user_field"); ok {
		role.IdentityUserField = v.(string)
	}
	if v, ok := d.GetOk("passport_number_field"); ok {
		role.PassportNumberField = v.(string)
	}
	if v, ok := d.GetOk("license_number_field"); ok {
		role.LicenseNumberField = v.(string)
	}
	if v, ok := d.GetOk("address1_field"); ok {
		role.Address1Field = v.(string)
	}
	if v, ok := d.GetOk("address2_field"); ok {
		role.Address2Field = v.(string)
	}
	if v, ok := d.GetOk("address3_field"); ok {
		role.Address3Field = v.(string)
	}
	if v, ok := d.GetOk("city_field"); ok {
		role.CityField = v.(string)
	}
	if v, ok := d.GetOk("state_field"); ok {
		role.StateField = v.(string)
	}
	if v, ok := d.GetOk("postal_code_field"); ok {
		role.PostalCodeField = v.(string)
	}
	if v, ok := d.GetOk("country_field"); ok {
		role.CountryField = v.(string)
	}

	// Validate required fields.
	if role.SourcePath == "" {
		return logical.ErrorResponse("source_path is required"), nil
	}
	if role.CipherName == "" {
		return logical.ErrorResponse("cipher_name is required"), nil
	}

	// Store the role.
	if err := b.writeRole(ctx, req.Storage, role); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleDelete deletes a role and its associated Vaultwarden cipher.
func (b *vaultwardenBackend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Read role to check for an associated cipher.
	role, err := b.readRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	// If the role has a synced cipher, attempt to delete it from Vaultwarden.
	// This is best-effort — the role is deleted regardless.
	if role != nil && role.CipherID != "" {
		if delErr := b.deleteCipherForRole(ctx, req.Storage, role); delErr != nil {
			b.logger.Warn("failed to cascade-delete cipher on role deletion",
				"role", name, "cipher_id", role.CipherID, "error", delErr)
		}
	}

	if err := req.Storage.Delete(ctx, "role/"+name); err != nil {
		return nil, fmt.Errorf("deleting role: %w", err)
	}

	return nil, nil
}

// readRole reads a role from storage.
func (b *vaultwardenBackend) readRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, fmt.Errorf("reading role from storage: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var role roleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("decoding role: %w", err)
	}

	return &role, nil
}

// writeRole writes a role to storage.
func (b *vaultwardenBackend) writeRole(ctx context.Context, s logical.Storage, role *roleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+role.Name, role)
	if err != nil {
		return fmt.Errorf("creating role storage entry: %w", err)
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("storing role: %w", err)
	}
	return nil
}
