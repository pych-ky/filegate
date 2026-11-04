package fixtures

import (
	"flag"
	"io"
	"os"

	"filegate.local/filegate/internal/freshclamadapter"
)

func Run(arguments []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("filegate-fixtures", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "", "")
	suite := flags.String("suite", "basic", "")
	work := flags.String("work", "", "")
	result := flags.String("output", "", "")
	library := flags.String("library", freshclamadapter.LibraryPath, "")
	control := flags.String("host-control", "", "")
	archive := flags.String("corpus", "/contracts/fixtures.tar.gz", "")
	manifest := flags.String("corpus-manifest", "/contracts/corpus-v1.json", "")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 {
		return invalid
	}
	switch *mode {
	case "format-contract":
		return FormatContracts(*archive, *manifest, *work, *result)
	case "extract-corpus":
		corpus, err := ExtractCorpus(*archive, *manifest, *work, false)
		if err == nil && *result != "" {
			err = write(*result, map[string]any{"schema": 1, "kind": "immutable_corpus_extraction_only", "archive_sha256": corpus.ArchiveSHA256,
				"file_count": corpus.FileCount, "bytes": corpus.UncompressedBytes, "case_counts": corpus.CaseCounts, "all_bytes_verified": true, "vm_executed": false, "product_acceptance": false})
		}
		return err
	case "freshclam":
		return Freshclam(*library, *work, *result, *control, input, output)
	case "freshclam-library":
		if !guest() {
			return invalid
		}
		stdout, _, code, err := command([]string{"/filegate-freshclam", "--library", *library, "--verify-only"}, nil, 1<<20, []string{"PATH=/bin:/usr/bin", "LC_ALL=C"})
		var record map[string]any
		if err != nil || code != 0 || decode(stdout, &record) != nil || record["fixed_adapter_verified"] != true {
			return invalid
		}
		_, err = output.Write(stdout)
		return err
	case "av":
		return RunAV(*suite, *work, *result)
	default:
		return invalid
	}
}

func Main(arguments []string) int {
	if err := Run(arguments, os.Stdin, os.Stdout); err != nil {
		_, _ = io.WriteString(os.Stderr, "FIXTURE_VERIFICATION_FAILED\n")
		return 2
	}
	return 0
}
