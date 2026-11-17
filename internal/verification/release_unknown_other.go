//go:build !darwin

package verification

import "errors"

func releaseUnknownStat(path string) (Object, error) {
	return nil, errors.New("RELEASE_UNKNOWN_REQUIRES_DARWIN")
}

func releaseUnknownMove(fromDir, from, toDir, to string) error {
	return errors.New("RELEASE_UNKNOWN_REQUIRES_DARWIN")
}
