package av

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"regexp"
	"strings"
	"unicode/utf8"
)

const StdoutLimit = 4 << 20
const StderrLimit = 1 << 20
const lineLimit = 4096

var signatureName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$`)

type capture struct {
	data     bytes.Buffer
	hash     hash.Hash
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func newCapture(limit int, cancel context.CancelFunc) *capture {
	return &capture{hash: sha256.New(), limit: limit, cancel: cancel}
}

func (c *capture) Write(body []byte) (int, error) {
	remaining := c.limit + 1 - c.data.Len()
	n := min(len(body), remaining)
	c.data.Write(body[:n])
	c.hash.Write(body[:n])
	if c.data.Len() > c.limit {
		c.overflow = true
		c.cancel()
		return n, invalid
	}
	return n, nil
}

func (c *capture) digest() string { return hex.EncodeToString(c.hash.Sum(nil)) }

func found(signature string) (string, string) {
	switch {
	case strings.HasPrefix(signature, "Heuristics.Limits.Exceeded."):
		return "hold", "LIMIT_EXCEEDED"
	case strings.HasPrefix(signature, "Heuristics.Encrypted."):
		return "hold", "ENCRYPTED_ARCHIVE"
	case signature == "Heuristics.OLE2.ContainsMacros":
		return "hold", "ACTIVE_CONTENT_REQUIRES_REVIEW"
	case strings.HasPrefix(signature, "Heuristics."):
		return "hold", "SCANNER_ERROR"
	default:
		return "detected", "MALWARE_DETECTED"
	}
}

func markError(object *ObjectResult, reason string) {
	object.Status, object.ReasonCode = "error", reason
	object.SignatureSHA256 = ""
	object.NormalResultPresent = false
}

func normalize(result *Result, paths []string, stdout, stderr *capture) {
	result.StdoutBytes, result.StdoutSHA256 = int64(stdout.data.Len()), stdout.digest()
	result.StderrBytes, result.StderrSHA256 = int64(stderr.data.Len()), stderr.digest()
	indices := make(map[string]int, len(paths))
	for index, path := range paths {
		indices[path] = index
	}
	seen := make(map[int]bool, len(paths))
	streamFailure := stdout.overflow || stderr.overflow || stderr.data.Len() != 0
	ambiguous := stderr.data.Len() != 0 || !utf8.Valid(stdout.data.Bytes())
	body := stdout.data.String()
	if body != "" && !strings.HasSuffix(body, "\n") {
		streamFailure, ambiguous = true, true
	}
	lines := strings.Split(body, "\n")
	for lineIndex, line := range lines {
		if line == "" && lineIndex == len(lines)-1 {
			continue
		}
		if len(line) > lineLimit || strings.ContainsAny(line, "\x00\r") {
			streamFailure, ambiguous = true, true
			continue
		}
		name, status, ok := strings.Cut(line, ": ")
		index, exists := indices[name]
		if !ok || !exists {
			streamFailure = true
			if !strings.HasPrefix(line, "LibClamAV Warning:") && !strings.HasPrefix(line, "LibClamAV Error:") && !strings.HasPrefix(line, "WARNING:") && !strings.HasPrefix(line, "ERROR:") {
				ambiguous = true
			}
			continue
		}
		object := &result.Objects[index]
		if seen[index] {
			markError(object, "SCANNER_ERROR")
			streamFailure = true
			continue
		}
		seen[index] = true
		object.NormalResultPresent = true
		switch {
		case status == "OK" && object.ByteSize > 0, status == "Empty file" && object.ByteSize == 0:
			object.Status, object.ReasonCode = "clean", ""
		case strings.HasSuffix(status, " FOUND") && signatureName.MatchString(strings.TrimSuffix(status, " FOUND")):
			signature := strings.TrimSuffix(status, " FOUND")
			object.Status, object.ReasonCode = found(signature)
			object.SignatureSHA256 = hexDigest([]byte(signature))
		case strings.HasSuffix(status, " ERROR") && len(status) <= 1024:
			object.Status, object.ReasonCode = "error", "SCANNER_ERROR"
			streamFailure = true
		default:
			markError(object, "SCANNER_ERROR")
			streamFailure, ambiguous = true, true
		}
	}
	if ambiguous {
		for index := range result.Objects {
			if result.Objects[index].Status == "detected" {
				markError(&result.Objects[index], "SCANNER_ERROR")
			}
		}
	}
	foundCount := 0
	for _, object := range result.Objects {
		if object.Status == "detected" || object.Status == "hold" {
			foundCount++
		}
	}
	if result.ExitCode != nil && ((*result.ExitCode == 0 && foundCount != 0) || (*result.ExitCode == 1 && foundCount == 0)) {
		streamFailure = true
		for index := range result.Objects {
			if result.Objects[index].Status == "detected" || result.Objects[index].Status == "hold" {
				markError(&result.Objects[index], "SCANNER_ERROR")
			}
		}
	}
	for index := range result.Objects {
		object := &result.Objects[index]
		if !object.InputVerified {
			reason := object.verificationFailure
			if reason == "" {
				reason = "SCANNER_ERROR"
			}
			markError(object, reason)
			streamFailure = true
		}
		if object.Status == "pending" || object.Status == "error" {
			streamFailure = true
		}
	}
	if !result.BindingVerified {
		streamFailure = true
	}
	if streamFailure && result.ProcessStatus != "timed_out" {
		result.ProcessStatus = "failed"
	}
	finalize(result)
}

func finalize(result *Result) {
	result.ReasonCodes = []string{}
	result.NormalResultCount = 0
	result.ConfirmedDetections = []Detection{}
	for _, object := range result.Objects {
		if object.NormalResultPresent {
			result.NormalResultCount++
		}
		if object.ReasonCode != "" && object.ReasonCode != "MALWARE_DETECTED" {
			result.reason(object.ReasonCode)
		}
		if object.ReasonCode == "INPUT_HASH_MISMATCH" {
			result.reason("SCANNER_ERROR")
		}
		if result.BindingVerified && object.Status == "detected" && object.InputVerified && object.NormalResultPresent {
			result.ConfirmedDetections = append(result.ConfirmedDetections, Detection{ObjectID: object.ObjectID, SHA256: object.SHA256, ByteSize: object.ByteSize, ReasonCode: "MALWARE_DETECTED", SignatureSHA256: object.SignatureSHA256})
		}
	}
	if !result.BindingVerified || result.ProcessStatus == "failed" {
		result.reason("SCANNER_ERROR")
	}
	if result.ProcessStatus == "timed_out" {
		result.reason("SCAN_TIMEOUT")
	}
	result.ResultsComplete = result.BindingVerified && result.ProcessStatus == "completed" && result.NormalResultCount == result.RequiredInputCount && len(result.ReasonCodes) == 0
	result.AVResult = "inconclusive"
	if len(result.ConfirmedDetections) != 0 {
		result.AVResult = "detected"
	} else if result.ResultsComplete {
		result.AVResult = "clean"
	}
}
