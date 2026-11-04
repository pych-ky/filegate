package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"syscall"
)

const productPolicy = "filegate-product-scan-v4"
const productReportLimit = 32 * 1024 * 1024

type startRequest struct {
	JobID     string          `json:"job_id"`
	AttemptID string          `json:"attempt_id"`
	SHA256    string          `json:"sha256"`
	Size      int64           `json:"byte_size"`
	Policy    string          `json:"policy_digest"`
	Fixture   string          `json:"fixture"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type productMetadata struct {
	DisplayName       string `json:"display_name,omitempty"`
	DeclaredMediaType string `json:"declared_media_type,omitempty"`
	ExpectedType      string `json:"expected_type,omitempty"`
}

func validStart(start startRequest) bool {
	if updateImage() || start.Fixture == "product-update" {
		return start.Fixture == "product-update" && validUpdateStart(start)
	}
	if start.Fixture != "product-inspect" {
		return start.Size >= 0 && start.Size <= 1024*1024 && len(start.SHA256) == 64 && start.JobID == "probe-job" && start.AttemptID == "probe-attempt" && start.Policy == "stage0-synthetic-only" && len(start.Metadata) == 0 && isFixture(start.Fixture)
	}
	if start.Size < 0 || start.Size > 250*1024*1024 || start.Policy != productPolicy || !regexp.MustCompile(`^job_[0-9a-f]{32}$`).MatchString(start.JobID) || !regexp.MustCompile(`^attempt_[0-9a-f]{32}$`).MatchString(start.AttemptID) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(start.SHA256) || len(start.Metadata) == 0 || len(start.Metadata) > 16384 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(start.Metadata))
	decoder.DisallowUnknownFields()
	var metadata productMetadata
	return decoder.Decode(&metadata) == nil && decoder.Decode(new(any)) == io.EOF && len(metadata.DisplayName) <= 2048 && len(metadata.DeclaredMediaType) <= 256 && len(metadata.ExpectedType) <= 32
}

func productWorker() {
	if noNewPrivileges() != nil {
		os.Exit(2)
	}
	if syscall.Exec("/filegate-worker", []string{"filegate-worker", "--mode", "scan", "--metadata-file", "/job/input/metadata.json"}, os.Environ()) != nil {
		os.Exit(2)
	}
}

func runProduct(start startRequest, send func(any)) {
	reject := func(reason string) {
		if reason == "WORKSPACE_IO_ERROR" {
			workspace := fsRecord("/job")
			if workspace["reason"] == "" {
				workspace["reason"] = reason
			}
			send(map[string]any{"event": "product_error", "reason": reason, "job_id": start.JobID,
				"attempt_id": start.AttemptID, "input_sha256": start.SHA256, "byte_size": start.Size,
				"policy_digest": start.Policy, "workspace": workspace})
			return
		}
		send(map[string]any{"event": "product_error", "reason": reason})
	}
	if installProductDefinitionProfile() != nil {
		reject("INCOMPLETE_REQUIRED_CHECKS")
		return
	}
	metadata, err := os.OpenFile("/job/input/metadata.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0444)
	if err != nil {
		reject("WORKSPACE_IO_ERROR")
		return
	}
	n, writeErr := metadata.Write(start.Metadata)
	syncErr, closeErr := metadata.Sync(), metadata.Close()
	if writeErr != nil || n != len(start.Metadata) || syncErr != nil || closeErr != nil {
		reject("WORKSPACE_IO_ERROR")
		return
	}
	directory, err := os.Open("/job/input")
	if err != nil {
		reject("WORKSPACE_IO_ERROR")
		return
	}
	syncErr, closeErr = directory.Sync(), directory.Close()
	if syncErr != nil || closeErr != nil {
		reject("WORKSPACE_IO_ERROR")
		return
	}
	command := restrictedWorker("--product-worker")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=/job/adapter-tmp", "TMP=/job/adapter-tmp", "TEMP=/job/adapter-tmp"}
	diagnostics := &diagnosticDigest{hash: sha256.New()}
	command.Stderr = diagnostics
	progressReader, progressWriter, err := os.Pipe()
	if err != nil {
		reject("INCOMPLETE_REQUIRED_CHECKS")
		return
	}
	command.ExtraFiles = []*os.File{progressWriter}
	pipe, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		progressReader.Close()
		progressWriter.Close()
		reject("INCOMPLETE_REQUIRED_CHECKS")
		return
	}
	progressWriter.Close()
	progressDone := make(chan bool, 1)
	go func() {
		defer progressReader.Close()
		scanner := bufio.NewScanner(progressReader)
		scanner.Buffer(make([]byte, 1024), 1025)
		count, valid := 0, true
		for scanner.Scan() {
			count++
			line := append([]byte(nil), scanner.Bytes()...)
			if count > 3 || len(line) > 1024 || !json.Valid(line) {
				valid = false
				command.Process.Kill()
				break
			}
			send(map[string]any{"event": "product_progress", "job_id": start.JobID, "attempt_id": start.AttemptID, "input_sha256": start.SHA256, "progress": json.RawMessage(line)})
		}
		if scanner.Err() != nil {
			command.Process.Kill()
		}
		progressDone <- valid && scanner.Err() == nil
	}()
	body, readErr := io.ReadAll(io.LimitReader(pipe, productReportLimit+1))
	if readErr != nil || len(body) > productReportLimit {
		command.Process.Kill()
		command.Wait()
		<-progressDone
		reject("REPORT_VALIDATION_FAILED")
		return
	}
	waitErr := command.Wait()
	progressValid := <-progressDone
	if waitErr != nil || diagnostics.ioError || !progressValid {
		reject("INCOMPLETE_REQUIRED_CHECKS")
		return
	}
	var worker struct {
		SchemaVersion int             `json:"schema_version"`
		Result        json.RawMessage `json:"result"`
		AV            json.RawMessage `json:"av"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var result, avResult map[string]any
	if decoder.Decode(&worker) != nil || decoder.Decode(new(any)) != io.EOF || worker.SchemaVersion != 1 || json.Unmarshal(worker.Result, &result) != nil || result == nil || json.Unmarshal(worker.AV, &avResult) != nil || avResult == nil {
		reject("REPORT_VALIDATION_FAILED")
		return
	}
	report := map[string]any{"schema_version": 2, "event": "product_result", "job_id": start.JobID, "attempt_id": start.AttemptID, "policy_digest": start.Policy,
		"input": map[string]any{"sha256": start.SHA256, "byte_size": start.Size}, "worker_uid": 65534, "report_complete": true,
		"manifest_complete": result["structure_status"] == "ACCEPT_FORMAT_STRUCTURE" && result["structure_checks_complete"] == true && result["format_checks_complete"] == true,
		"av_process_status": avResult["process_status"], "av_result": avResult["av_result"], "result": worker.Result, "av": worker.AV}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > productReportLimit {
		reject("REPORT_VALIDATION_FAILED")
		return
	}
	file, err := os.OpenFile("/job/metadata/product-result.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
	if err != nil {
		reject("WORKSPACE_IO_ERROR")
		return
	}
	n, writeErr = file.Write(encoded)
	syncErr, closeErr = file.Sync(), file.Close()
	if writeErr != nil || n != len(encoded) || syncErr != nil || closeErr != nil {
		reject("WORKSPACE_IO_ERROR")
		return
	}
	directory, err = os.Open("/job/metadata")
	if err != nil {
		reject("WORKSPACE_IO_ERROR")
		return
	}
	syncErr, closeErr = directory.Sync(), directory.Close()
	if syncErr != nil || closeErr != nil {
		reject("WORKSPACE_IO_ERROR")
		return
	}
	send(report)
}
