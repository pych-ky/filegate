package inspect

import (
	"bytes"
	"math/bits"
)

// Info-ZIP extended timestamp ("UT") and UID/GID ("ux") blocks are the only extra fields ZIP32 Profile 2 accepts.
const (
	extendedTimestamp = 0x5455
	unixOwner         = 0x7875
)

type extraBlock struct {
	id   uint16
	data []byte
}

// extraBlocks frames one extra area: every byte must belong to a complete ID/size record.
func extraBlocks(p []byte) ([]extraBlock, error) {
	var blocks []extraBlock
	for len(p) > 0 {
		if len(p) < 4 {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		size := int(u16(p[2:]))
		if size > len(p)-4 {
			return nil, fail("ARCHIVE_CORRUPT")
		}
		blocks = append(blocks, extraBlock{id: u16(p), data: p[4 : 4+size]})
		p = p[4+size:]
	}
	return blocks, nil
}

// knownBlocks maps the accepted IDs of one framed area; any other ID or a repeated ID is outside the profile.
func knownBlocks(blocks []extraBlock) (map[uint16][]byte, error) {
	known := make(map[uint16][]byte, len(blocks))
	for _, b := range blocks {
		if b.id != extendedTimestamp && b.id != unixOwner {
			return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
		}
		if _, repeated := known[b.id]; repeated {
			return nil, fail("ARCHIVE_PROFILE_UNSUPPORTED")
		}
		known[b.id] = b.data
	}
	return known, nil
}

// unixMetadata validates the local and central extra areas of one entry. Values are checked for consistency only and are
// never applied to extracted files.
func unixMetadata(local, central []byte) error {
	localBlocks, err := extraBlocks(local)
	if err != nil {
		return err
	}
	centralBlocks, err := extraBlocks(central)
	if err != nil {
		return err
	}
	l, err := knownBlocks(localBlocks)
	if err != nil {
		return err
	}
	c, err := knownBlocks(centralBlocks)
	if err != nil {
		return err
	}
	if err := blockLayouts(l, localTimestamp); err != nil {
		return err
	}
	if err := blockLayouts(c, centralTimestamp); err != nil {
		return err
	}
	if len(l) != len(c) {
		return fail("ARCHIVE_CORRUPT")
	}
	for id, p := range l {
		q, ok := c[id]
		if !ok {
			return fail("ARCHIVE_CORRUPT")
		}
		switch id {
		case extendedTimestamp:
			// The central block carries only the modification time; its flags may repeat the local ones or name only it.
			if q[0] != 0x01 && q[0] != p[0] || !bytes.Equal(p[1:5], q[1:5]) {
				return fail("ARCHIVE_CORRUPT")
			}
		case unixOwner:
			if !bytes.Equal(p, q) {
				return fail("ARCHIVE_CORRUPT")
			}
		}
	}
	return nil
}

// blockLayouts checks the accepted blocks of one header, the timestamp first.
func blockLayouts(blocks map[uint16][]byte, timestamp func([]byte) error) error {
	if p, ok := blocks[extendedTimestamp]; ok {
		if err := timestamp(p); err != nil {
			return err
		}
	}
	if p, ok := blocks[unixOwner]; ok {
		return owner(p)
	}
	return nil
}

// localTimestamp requires the modification time, no reserved flag bits and one 4-byte time per flag bit.
func localTimestamp(p []byte) error {
	if len(p) == 0 {
		return fail("ARCHIVE_CORRUPT")
	}
	if p[0]&0x01 == 0 || p[0]&0xf8 != 0 {
		return fail("ARCHIVE_PROFILE_UNSUPPORTED")
	}
	if len(p) != 1+4*bits.OnesCount8(p[0]) {
		return fail("ARCHIVE_CORRUPT")
	}
	return nil
}

func centralTimestamp(p []byte) error {
	if len(p) == 0 {
		return fail("ARCHIVE_CORRUPT")
	}
	if p[0]&0xf8 != 0 {
		return fail("ARCHIVE_PROFILE_UNSUPPORTED")
	}
	if len(p) != 5 {
		return fail("ARCHIVE_CORRUPT")
	}
	return nil
}

// owner accepts version 1 with 4-byte UID and GID; other versions may use another layout and are not interpreted.
func owner(p []byte) error {
	if len(p) == 0 {
		return fail("ARCHIVE_CORRUPT")
	}
	if p[0] != 1 {
		return fail("ARCHIVE_PROFILE_UNSUPPORTED")
	}
	if len(p) < 2 || len(p) < 3+int(p[1]) || len(p) != 3+int(p[1])+int(p[2+int(p[1])]) {
		return fail("ARCHIVE_CORRUPT")
	}
	if p[1] != 4 || p[2+int(p[1])] != 4 {
		return fail("ARCHIVE_PROFILE_UNSUPPORTED")
	}
	return nil
}
