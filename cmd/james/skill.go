package main

import (
	"bytes"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

//go:embed skill/SKILL.md
var skillMD []byte

func skillInstall(args []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("skill-install", flag.ExitOnError)
	dir := fs.String("dir", filepath.Join(home, ".claude", "skills"), "skills directory")
	_ = fs.Parse(args)

	target := filepath.Join(*dir, "james")
	path := filepath.Join(target, "SKILL.md")
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, skillMD) {
		fmt.Println("up to date:", path)
		return nil
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	// O_NOFOLLOW: don't write through a symlink planted at the skill path.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%s is a symlink; remove it first", path)
		}
		return err
	}
	if _, err := f.Write(skillMD); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println("installed:", path)
	return nil
}
