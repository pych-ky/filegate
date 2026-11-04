package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"filegate.local/filegate/internal/buildtools"
)

func main() {
	defer func() {
		if failure := recover(); failure != nil {
			fmt.Fprintln(os.Stderr, failure)
			os.Exit(1)
		}
	}()
	os.Exit(run(os.Args[1:]))
}

func emit(value any) int {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if encoder.Encode(value) != nil {
		return 1
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, err)
	return 1
}

func run(args []string) int {
	flags := flag.NewFlagSet("filegate-dev", flag.ContinueOnError)
	repo := flags.String("repo", "", "source repository")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	args = flags.Args()
	if len(args) == 0 {
		return fail(fmt.Errorf("expected workspace, gate, build-scan, build-update, build-freshclam or verify-adapter"))
	}
	switch args[0] {
	case "workspace":
		return workspace(*repo, args[1:])
	case "gate":
		if len(args) != 1 {
			return 2
		}
		result, code, err := buildtools.Gate(*repo)
		if err != nil {
			return fail(err)
		}
		if emit(result) != 0 {
			return 1
		}
		return code
	case "build-scan":
		return buildScan(*repo, args[1:])
	case "build-update":
		return buildUpdate(*repo, args[1:])
	case "build-freshclam":
		return buildFreshclam(*repo, args[1:])
	case "verify-adapter":
		check := flag.NewFlagSet("verify-adapter", flag.ContinueOnError)
		bundle := check.String("bundle", "", "adopted external prebuilt adapter bundle")
		if check.Parse(args[1:]) != nil || check.NArg() != 0 || *bundle == "" {
			return 2
		}
		root, err := buildtools.Repository(*repo)
		if err != nil {
			return fail(err)
		}
		binding, err := buildtools.VerifyAdapter(*bundle, filepath.Join(root, "experiments/av"))
		if err != nil {
			return fail(err)
		}
		return emit(map[string]any{"verified": true, "scope": "adopted_prebuilt_consumer_dependencies_and_libraries", "mode": binding.Mode, "builder_results_sha256": binding.BuilderResultsSHA256, "artifact_manifest_sha256": binding.ArtifactManifestSHA256, "inputs_sha256": binding.InputsSHA256})
	default:
		return fail(fmt.Errorf("unknown development command: %s", args[0]))
	}
}

func workspace(repo string, args []string) int {
	flags := flag.NewFlagSet("workspace", flag.ContinueOnError)
	root := flags.String("root", "", "external verification workspace")
	verification := flags.String("verification", "", "shared verification root")
	if flags.Parse(args) != nil || len(flags.Args()) == 0 {
		return 2
	}
	args = flags.Args()
	options := buildtools.WorkspaceOptions{Repository: repo, Root: *root, Verification: *verification}
	if args[0] == "path" {
		if len(args) != 1 {
			return 2
		}
		path, err := buildtools.WorkspacePath(options)
		if err != nil {
			return fail(err)
		}
		fmt.Println(path)
		return 0
	}
	if args[0] == "sync" {
		if len(args) != 1 {
			return 2
		}
		result, _, err := buildtools.Workspace(context.Background(), options, nil, ".", os.Stdout, os.Stderr)
		if err != nil {
			return fail(err)
		}
		return emit(result)
	}
	if args[0] != "run" {
		return 2
	}
	runFlags := flag.NewFlagSet("workspace run", flag.ContinueOnError)
	cwd := runFlags.String("cwd", ".", "workspace-relative working directory")
	if runFlags.Parse(args[1:]) != nil || len(runFlags.Args()) == 0 {
		return 2
	}
	_, code, err := buildtools.Workspace(context.Background(), options, runFlags.Args(), *cwd, os.Stdout, os.Stderr)
	if err != nil {
		return fail(err)
	}
	return code
}
