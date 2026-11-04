package hostvm

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

func hashReader(r io.Reader, size int64) (string, error) {
	hash := sha256.New()
	n, e := io.CopyN(hash, r, size)
	if e != nil || n != size {
		return "", Error("CONTENT_TRUNCATED")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
