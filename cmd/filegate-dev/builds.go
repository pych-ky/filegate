package main

import (
	"context"
	"flag"

	"filegate.local/filegate/internal/buildtools"
)

func buildScan(repo string, args []string) int {
	flags := flag.NewFlagSet("build-scan", flag.ContinueOnError)
	baseline := flags.String("baseline", "", "verified readonly baseline workspace")
	baselineProof := flags.String("baseline-proof", "", "baseline construction proof")
	nativeProof := flags.String("native-proof", "", "native monitor proof")
	nativeBinary := flags.String("native-binary", "", "new qualified native binary, otherwise the verified baseline binary")
	freshclam := flags.String("freshclam-binary", "", "fixed Go/cgo adapter binary")
	freshclamBuild := flags.String("freshclam-build", "", "adapter build receipt")
	verification := flags.String("verification", "", "shared verification root")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *baseline == "" || *baselineProof == "" || *nativeProof == "" || *freshclam == "" || *freshclamBuild == "" {
		return 2
	}
	result, err := buildtools.BuildScan(context.Background(), buildtools.BuildOptions{Repository: repo, Verification: *verification, Baseline: *baseline, BaselineProof: *baselineProof, NativeProof: *nativeProof, NativeBinary: *nativeBinary, FreshclamBinary: *freshclam, FreshclamBuild: *freshclamBuild})
	if err != nil {
		return fail(err)
	}
	return emit(result)
}

func buildUpdate(repo string, args []string) int {
	flags := flag.NewFlagSet("build-update", flag.ContinueOnError)
	baseline := flags.String("baseline-build", "", "derived Go scan build receipt")
	adapter := flags.String("adapter-build", "", "fixed adapter artifact directory")
	proof := flags.String("proof", "", "native monitor proof")
	out := flags.String("out", "", "new external output")
	freshclam := flags.String("freshclam-binary", "", "fixed Go/cgo adapter binary")
	freshclamBuild := flags.String("freshclam-build", "", "adapter build receipt")
	reuse := flags.String("reuse-registration", "", "identical Go update artifact registration")
	verification := flags.String("verification", "", "shared verification root")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *baseline == "" || *adapter == "" || *proof == "" || *out == "" || *freshclam == "" || *freshclamBuild == "" {
		return 2
	}
	result, err := buildtools.BuildUpdate(context.Background(), buildtools.BuildOptions{Repository: repo, Verification: *verification, BaselineBuild: *baseline, AdapterBuild: *adapter, NativeProof: *proof, Out: *out, FreshclamBinary: *freshclam, FreshclamBuild: *freshclamBuild, ReuseRegistration: *reuse})
	if err != nil {
		return fail(err)
	}
	return emit(result)
}

func buildFreshclam(repo string, args []string) int {
	flags := flag.NewFlagSet("build-freshclam", flag.ContinueOnError)
	verification := flags.String("verification", "", "pinned local build-input root")
	out := flags.String("out", "", "new external output")
	checkInputs := flags.Bool("inputs-only", false, "verify pinned offline compiler closure without starting a container")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *verification == "" || (*out == "" && !*checkInputs) {
		return 2
	}
	result, err := buildtools.BuildFreshclam(context.Background(), buildtools.BuildOptions{Repository: repo, Verification: *verification, Out: *out, CheckInputs: *checkInputs})
	if result != nil {
		if code := emit(result); code != 0 {
			return code
		}
	}
	if err != nil {
		return fail(err)
	}
	return 0
}
