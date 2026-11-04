package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const productDefinitionProfile = "/.definitions/product-profile.json"
const productInstalledProfile = "/av/product-profile.json"

func readProductDefinitionProfile(allowHistorical bool) ([]byte, string, error) {
	f, err := os.OpenFile(productDefinitionProfile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0444 || owner.Uid != 0 || owner.Gid != 0 || owner.Nlink != 1 || info.Size() <= 0 || info.Size() > 64<<10 {
		return nil, "", errors.New("definition profile ownership invalid")
	}
	body, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(body)) != info.Size() || after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return nil, "", errors.New("definition profile changed")
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&fields) != nil || decoder.Decode(new(any)) != io.EOF || len(fields) != 8 {
		return nil, "", errors.New("definition profile invalid")
	}
	for _, name := range []string{"schema_version", "profile_id", "scanner_manifest_sha256", "configuration_sha256", "definition_set_sha256", "observation_sha256", "fixture_definitions_only", "definitions"} {
		if len(fields[name]) == 0 || bytes.Equal(fields[name], []byte("null")) {
			return nil, "", errors.New("definition profile field missing")
		}
	}
	var schema int
	var profile, scanner, configuration, observation string
	var fixture bool
	if json.Unmarshal(fields["schema_version"], &schema) != nil || schema != 1 ||
		json.Unmarshal(fields["profile_id"], &profile) != nil ||
		json.Unmarshal(fields["scanner_manifest_sha256"], &scanner) != nil ||
		json.Unmarshal(fields["configuration_sha256"], &configuration) != nil ||
		json.Unmarshal(fields["observation_sha256"], &observation) != nil ||
		json.Unmarshal(fields["fixture_definitions_only"], &fixture) != nil || fixture {
		return nil, "", errors.New("official definition profile required")
	}
	current := profile == "filegate-standard-av-1.4.6-limited-v2" && observation == "9911ded74d6240baf219dab9bb9b9cb185c913274dd63d42993d69df04dbcbca"
	historical := allowHistorical && profile == "filegate-standard-av-1.4.6-candidate-v1" && observation == "2820f79fce99925c4bbf2301c2bae1c1276e8940439ce61926aadb473be7dd2e"
	if (!current && !historical) || scanner != "47be9f07e65948d76d6cf46b38d2baf73cddcccd7562a7a3011e19af9d982b8c" ||
		configuration != "08eaa97d240dde9866c14e709bbf937dbff04c068e28676e690146b150ae7477" {
		return nil, "", errors.New("definition profile revision invalid")
	}
	digest := sha256.Sum256(body)
	return body, hex.EncodeToString(digest[:]), nil
}

func installProductDefinitionProfile() error {
	body, _, err := readProductDefinitionProfile(false)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(productInstalledProfile); !errors.Is(err, os.ErrNotExist) {
		return errors.New("product profile already present")
	}
	if body == nil {
		return nil
	}
	packages, err := filepath.Glob("/.packages/*.apk")
	if err != nil || len(packages) == 0 {
		return errors.New("scanner packages missing")
	}
	install := exec.Command("/sbin/apk", append([]string{"add", "--no-network"}, packages...)...)
	install.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TMPDIR=/job/adapter-tmp"}
	if err = install.Run(); err != nil {
		return err
	}
	profile, err := os.OpenFile(productInstalledProfile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0444)
	if err != nil {
		return err
	}
	n, writeErr := profile.Write(body)
	modeErr, syncErr, closeErr := profile.Chmod(0444), profile.Sync(), profile.Close()
	if writeErr != nil || n != len(body) || modeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("product profile installation failed")
	}
	directory, err := os.Open("/av")
	if err != nil {
		return err
	}
	syncErr, closeErr = directory.Sync(), directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("product profile synchronization failed")
	}
	return nil
}
