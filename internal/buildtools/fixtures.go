package buildtools

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"filegate.local/filegate/internal/av"
)

func writeFixture(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0444)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil {
		return err
	}
	return closed
}

func GenerateAVFixtures(repository, out, observation string) (map[string]any, error) {
	folder := filepath.Join(out, "product-fixtures")
	if err := os.MkdirAll(folder, 0700); err != nil {
		return nil, err
	}
	clean := []byte("FileGate synthetic clean fixture.\n")
	marker := []byte("FileGate harmless AV observation marker.\n")
	definition := []byte("FileGate.Harmless.Marker:0:*:46696c6547617465206861726d6c657373\n")
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for _, entry := range []struct {
		name      string
		body      []byte
		directory bool
	}{{"clean.txt", clean, false}, {"marker.txt", marker, false}, {"empty.txt", nil, false}, {"empty/", nil, true}} {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store, ModifiedDate: (2026-1980)<<9 | 1<<5 | 1}
		header.CreatorVersion = 3<<8 | 20
		header.ExternalAttrs = 0100600 << 16
		if entry.directory {
			header.ExternalAttrs = 0040755<<16 | 0x10
		}
		f, err := writer.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err = f.Write(entry.body); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	cases := []map[string]any{}
	for _, entry := range []struct {
		id, name, kind, result    string
		body                      []byte
		required, detected, empty int
	}{{"clean", "clean.txt", "txt", "clean", clean, 1, 0, 0}, {"marker", "marker.txt", "txt", "detected", marker, 1, 1, 0}, {"zero-byte", "zero-byte.txt", "txt", "clean", nil, 1, 0, 0}, {"zip-mixed", "zip-mixed.zip", "zip", "detected", data.Bytes(), 4, 2, 1}} {
		if err := writeFixture(filepath.Join(folder, entry.name), entry.body); err != nil {
			return nil, err
		}
		cases = append(cases, map[string]any{"id": entry.id, "input": entry.name, "expected_type": entry.kind, "sha256": digest(entry.body), "byte_size": len(entry.body), "expected_av_result": entry.result, "expected_required_count": entry.required, "expected_detected_count": entry.detected, "expected_empty_directories": entry.empty})
	}
	body, err := jsonBytes(map[string]any{"schema_version": 1, "cases": cases})
	if err != nil {
		return nil, err
	}
	if err = writeFixture(filepath.Join(folder, "manifest.json"), body); err != nil {
		return nil, err
	}
	if err = writeFixture(filepath.Join(out, "marker.ndb"), definition); err != nil {
		return nil, err
	}
	revision := av.CurrentRevision()
	actualObservation, err := SHA(observation)
	if err != nil {
		return nil, err
	}
	if actualObservation != revision.ObservationSHA256 {
		return nil, fmt.Errorf("current observation digest required")
	}
	definitions := []av.Definition{{Name: "marker.ndb", SHA256: digest(definition), ByteSize: int64(len(definition))}}
	profile := av.Profile{SchemaVersion: 1, ProfileID: revision.ProfileID, ScannerManifestSHA256: revision.ScannerManifestSHA256, ConfigurationSHA256: revision.ConfigurationSHA256, DefinitionSetSHA256: av.DefinitionDigest(definitions), ObservationSHA256: revision.ObservationSHA256, FixtureDefinitionsOnly: true, Definitions: definitions}
	body, err = jsonBytes(profile)
	if err != nil {
		return nil, err
	}
	if err = writeFixture(filepath.Join(out, "product-profile-fixture.json"), body); err != nil {
		return nil, err
	}
	files := map[string]string{}
	if err = filepath.Walk(out, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		name, err := filepath.Rel(out, path)
		if err != nil {
			return err
		}
		value, err := SHA(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(name)] = value
		return nil
	}); err != nil {
		return nil, err
	}
	record := map[string]any{"schema": 1, "fixture_definitions_only": true, "official_definitions_adopted": false, "implementation": "go", "observation_path": observation, "observation_sha256": actualObservation, "files_sha256": files, "source_profile": revision}
	body, err = jsonBytes(record)
	if err == nil {
		err = writeFixture(filepath.Join(out, "receipt.json"), body)
	}
	return record, err
}
