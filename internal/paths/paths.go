package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return h
}

func StateDir() string { return filepath.Join(home(), "Library", "Application Support", "james") }

func Socket() string { return filepath.Join(StateDir(), "james.sock") }

func LogDir() string { return filepath.Join(home(), "Library", "Logs", "james") }

func Config() string { return filepath.Join(home(), ".config", "james", "config.yaml") }

// PrivateDir creates dir with mode 0700, or checks an existing one is ours and private.
// The socket lives here, so another user must not be able to replace it.
func PrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read directory owner")
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by the current user", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}
