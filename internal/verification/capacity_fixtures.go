package verification

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filegate.local/filegate/internal/inspect"
)

// capacityCase fixes one capacity-boundary input from the intake and extraction limits, independently of any proof file.
type capacityCase struct {
	ID      string
	TXT     int64
	Members []int64
}

func capacityCases() []capacityCase {
	tenFiles := make([]int64, 10)
	for i := range tenFiles {
		tenFiles[i] = inspect.FileLimit
	}
	rest := inspect.TotalLimit - 10*inspect.FileLimit
	return []capacityCase{
		{ID: "input-262144001", TXT: inspect.InputLimit + 1},
		{ID: "input-262144000", TXT: inspect.InputLimit},
		{ID: "file-at", Members: []int64{inspect.FileLimit}},
		{ID: "file-over", Members: []int64{inspect.FileLimit + 1}},
		{ID: "cumulative-at", Members: append(append([]int64{}, tenFiles...), rest)},
		{ID: "cumulative-over", Members: append(append([]int64{}, tenFiles...), rest+1)},
	}
}

// capacityText streams ASCII words chosen by a SHA-256 counter stream: valid TXT whose deflate ratio stays between the input and 100:1 limits.
type capacityText struct {
	seed  string
	block []byte
	count uint64
	left  []byte
}

var capacityWords = []string{"alpha ", "bravo ", "carbon ", "delta ", "ember ", "fjord ", "gamma ", "harbor ", "indigo ", "jasper ", "kelvin ", "lumen ", "matrix ", "nickel ", "orbit ", "prism\n"}

func (t *capacityText) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(t.left) == 0 {
			if len(t.block) == 0 {
				sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", t.seed, t.count)))
				t.count++
				t.block = sum[:]
			}
			b := t.block[0]
			t.block = t.block[1:]
			t.left = []byte(capacityWords[b>>4] + capacityWords[b&15])
		}
		copied := copy(p[n:], t.left)
		t.left = t.left[copied:]
		n += copied
	}
	return n, nil
}

func writeCapacityTXT(path, seed string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	_, err = io.CopyN(w, &capacityText{seed: seed}, size)
	if err == nil {
		err = w.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if closed := f.Close(); err == nil {
		err = closed
	}
	return err
}

func writeCapacityZIP(path, seed string, members []int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	archive := zip.NewWriter(bufio.NewWriterSize(f, 1<<20))
	for i, size := range members {
		// No modification time keeps the writer from adding the extended-timestamp extra field the ZIP profile rejects.
		header := &zip.FileHeader{Name: fmt.Sprintf("member-%02d.txt", i), Method: zip.Deflate}
		header.Flags |= 0x800
		member, e := archive.CreateHeader(header)
		if e == nil {
			_, e = io.CopyN(member, &capacityText{seed: fmt.Sprintf("%s/%d", seed, i)}, size)
		}
		if e != nil {
			archive.Close()
			f.Close()
			return e
		}
	}
	err = archive.Close()
	if err == nil {
		err = f.Sync()
	}
	if closed := f.Close(); err == nil {
		err = closed
	}
	return err
}

func capacityFileDigest(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// GenerateCapacityFixtures writes the six capacity-boundary inputs into a new directory and returns their proof rows.
func GenerateCapacityFixtures(out string) ([]Object, error) {
	if err := os.Mkdir(out, 0700); err != nil {
		return nil, err
	}
	for _, c := range capacityCases() {
		path := filepath.Join(out, c.ID+".zip")
		var err error
		if c.Members == nil {
			path = filepath.Join(out, c.ID+".txt")
			err = writeCapacityTXT(path, c.ID, c.TXT)
		} else {
			err = writeCapacityZIP(path, c.ID, c.Members)
		}
		if err != nil {
			return nil, err
		}
	}
	return VerifyCapacityFixtures(out, nil)
}

// VerifyCapacityFixtures checks the six inputs against the limit-derived sizes and ZIP geometry and, when rows is given, against those proof rows; it returns the observed rows.
func VerifyCapacityFixtures(dir string, rows []Object) ([]Object, error) {
	cases := capacityCases()
	if rows != nil && len(rows) != len(cases) {
		return nil, errors.New("CAPACITY_PROOF_CASE_SET")
	}
	observed := []Object{}
	for i, c := range cases {
		name := c.ID + ".zip"
		if c.Members == nil {
			name = c.ID + ".txt"
		}
		path := filepath.Join(dir, name)
		sum, size, err := capacityFileDigest(path)
		if err != nil || size > inspect.InputLimit && c.TXT != inspect.InputLimit+1 || c.Members == nil && size != c.TXT {
			return nil, fmt.Errorf("CAPACITY_INPUT_SIZE:%s", c.ID)
		}
		row := Object{"id": c.ID, "path": name, "byte_size": size, "sha256": sum}
		if c.Members != nil {
			archive, err := zip.OpenReader(path)
			if err != nil || len(archive.File) != len(c.Members) {
				return nil, fmt.Errorf("CAPACITY_ZIP_GEOMETRY:%s", c.ID)
			}
			members := []Object{}
			for j, file := range archive.File {
				if file.Name != fmt.Sprintf("member-%02d.txt", j) || file.Method != zip.Deflate || len(file.Extra) != 0 || int64(file.UncompressedSize64) != c.Members[j] || file.UncompressedSize64 > file.CompressedSize64*100 {
					archive.Close()
					return nil, fmt.Errorf("CAPACITY_ZIP_GEOMETRY:%s", c.ID)
				}
				reader, err := file.Open()
				if err != nil {
					archive.Close()
					return nil, err
				}
				h := sha256.New()
				n, err := io.Copy(h, reader)
				reader.Close()
				if err != nil || n != c.Members[j] {
					archive.Close()
					return nil, fmt.Errorf("CAPACITY_ZIP_MEMBER:%s", c.ID)
				}
				members = append(members, Object{"name": file.Name, "uncompressed_bytes": n, "compressed_bytes": int64(file.CompressedSize64), "sha256": hex.EncodeToString(h.Sum(nil))})
			}
			archive.Close()
			row["members"] = members
		}
		if rows != nil && string(Encoded(rows[i])) != string(Encoded(row)) {
			return nil, fmt.Errorf("CAPACITY_PROOF_MISMATCH:%s", c.ID)
		}
		observed = append(observed, row)
	}
	return observed, nil
}
