//go:build !darwin

package verification

import "errors"

func vmCloneFile(source, target string) error {
	return errors.New("VM_FIXTURE_WORKSPACE_REQUIRES_DARWIN")
}
