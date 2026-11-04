package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// This experiment fixes path comparison semantics before the ZIP validator exists.
func main() {
	out := flag.String("out", "", "new artifact directory")
	flag.Parse()
	if *out == "" || runtime.Version() != "go1.27.3" || norm.Version != "17.0.0" || cases.UnicodeVersion != "17.0.0" {
		fmt.Fprintln(os.Stderr, "Go 1.27.3 and Unicode 17.0.0 are required")
		os.Exit(2)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0700); err != nil {
		panic(err)
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		panic(err)
	}
	fold := cases.Fold()
	key := func(s string) string { return norm.NFC.String(fold.String(norm.NFC.String(s))) }
	fixtures := []struct {
		A, B  string
		Equal bool
	}{
		{"A", "a", true}, {"caf\u00e9", "cafe\u0301", true}, {"\u00df", "ss", true},
		{"\u03c2", "\u03c3", true}, {"\u212a", "k", true}, {"\u0130", "i", false},
		{"\u0131", "i", false}, {"\uff21", "a", false}, {"\u65e5\u672c\u8a9e", "\u65e5\u672c\u8a9e", true},
	}
	results := []map[string]any{}
	passed := true
	for _, f := range fixtures {
		a, b := key(f.A), key(f.B)
		ok := (a == b) == f.Equal
		passed = passed && ok
		results = append(results, map[string]any{"a": f.A, "b": f.B, "expected_equal": f.Equal, "key_a": a, "key_b": b, "passed": ok})
	}
	sources := map[string]string{}
	for _, name := range []string{"norm_probe.go", "go.mod", "go.sum"} {
		data, err := os.ReadFile(name)
		if err != nil {
			panic(err)
		}
		h := sha256.Sum256(data)
		sources[name] = hex.EncodeToString(h[:])
		if err := os.WriteFile(filepath.Join(*out, name), data, 0600); err != nil {
			panic(err)
		}
	}
	report := map[string]any{"schema": 1, "scope": "path comparison primitive, not ZIP validation", "go": runtime.Version(), "unicode": norm.Version,
		"module": "golang.org/x/text@v0.43.0", "source_sha256": sources, "results": results, "all_passed": passed, "product_enabled": false}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "results.json"), append(data, '\n'), 0600); err != nil {
		panic(err)
	}
	fmt.Printf("%d cases; all_passed=%v\n", len(results), passed)
	if !passed {
		os.Exit(1)
	}
}
