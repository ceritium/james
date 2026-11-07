// james-probe resolves references against real providers and prints only a
// fingerprint of each value, to check provider wiring without exposing secrets.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ceritium/james/internal/provider"
	"github.com/ceritium/james/internal/provider/onepassword"
)

func main() {
	var err error
	account := flag.String("account", "", "1Password account name, sign-in address or UUID")
	timeout := flag.Duration("timeout", 2*time.Minute, "time allowed for the 1Password authorization prompt")
	find := flag.String("find", "", "item ID to locate; prints field names and refs, never values")
	vaults := flag.Bool("vaults", false, "list vault IDs and names")
	flag.Parse()

	if *find != "" || *vaults {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		if *vaults {
			err = listVaults(ctx, *account)
		} else {
			err = findItem(ctx, *account, *find)
		}
		if err != nil {
			fail(err)
		}
		return
	}
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: james-probe [-account NAME] (-find ITEM_ID | op://vault/item/field ...)")
		os.Exit(2)
	}

	registry, err := provider.NewRegistry(onepassword.New(onepassword.Options{
		DefaultAccount:  *account,
		IntegrationName: "james-probe",
	}))
	if err != nil {
		fail(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	status := 0
	for _, raw := range flag.Args() {
		ref, err := registry.Parse(raw, "")
		if err != nil {
			fmt.Printf("%s\tinvalid: %v\n", raw, err)
			status = 1
			continue
		}
		start := time.Now()
		v, err := registry.Resolve(ctx, ref)
		if err != nil {
			fmt.Printf("%s\terror: %v\n", raw, err)
			status = 1
			continue
		}
		sum := sha256.Sum256(v.Bytes())
		fmt.Printf("%s\tok len=%d sha256=%s… (%s)\n", raw, v.Len(), hex.EncodeToString(sum[:4]), time.Since(start).Round(time.Millisecond))
		v.Wipe()
	}
	os.Exit(status)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
