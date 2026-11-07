package main

import (
	"context"
	"fmt"

	onepassword "github.com/1password/onepassword-sdk-go"
)

func listVaults(ctx context.Context, account string) error {
	client, err := onepassword.NewClient(ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo("james-probe", "dev"),
	)
	if err != nil {
		return err
	}
	vaults, err := client.Vaults().List(ctx)
	if err != nil {
		return fmt.Errorf("list vaults: %w", err)
	}
	for _, v := range vaults {
		fmt.Printf("%s\t%s\n", v.ID, v.Title)
	}
	return nil
}

// findItem locates an item by ID across vaults and prints field names and
// types only. Items().Get returns values too; they must never be printed.
func findItem(ctx context.Context, account, itemID string) error {
	client, err := onepassword.NewClient(ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo("james-probe", "dev"),
	)
	if err != nil {
		return err
	}
	vaults, err := client.Vaults().List(ctx)
	if err != nil {
		return fmt.Errorf("list vaults: %w", err)
	}
	for _, vault := range vaults {
		item, err := client.Items().Get(ctx, vault.ID, itemID)
		if err != nil {
			continue
		}
		fmt.Printf("vault %q (%s)\nitem  %q category=%s\n", vault.Title, vault.ID, item.Title, item.Category)
		for _, f := range item.Fields {
			fmt.Printf("  field %-20q type=%-12s ref=op://%s/%s/%s\n", f.Title, f.FieldType, vault.ID, item.ID, f.ID)
		}
		return nil
	}
	return fmt.Errorf("item %s not found in %d vaults", itemID, len(vaults))
}
