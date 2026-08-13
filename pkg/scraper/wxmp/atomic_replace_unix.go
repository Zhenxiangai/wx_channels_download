//go:build !windows

package wxmp

import "os"

func atomic_replace_file(source, target string) error {
	return os.Rename(source, target)
}
