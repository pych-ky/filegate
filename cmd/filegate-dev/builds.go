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

// buildHost also serves build-guest, which may additionally replace the fixed replaceable guest binaries in the copied image, and
// build-inspector, which may also replace the ZIP inspector binaries and the reviewed ZIP contract.
func buildHost(repo string, args []string, name string) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	baseline := flags.String("baseline", "", "existing scan build workspace")
	nativeProof := flags.String("native-proof", "", "native monitor proof of the baseline build")
	nativeBinary := flags.String("native-binary", "", "new qualified native binary")
	replacementProof := flags.String("replacement-native-proof", "", "native monitor proof of the new binary")
	verification := flags.String("verification", "", "shared verification root")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *baseline == "" || *nativeProof == "" || (*nativeBinary == "") != (*replacementProof == "") {
		return 2
	}
	result, err := buildtools.BuildHost(context.Background(), buildtools.BuildOptions{Repository: repo, Verification: *verification, Baseline: *baseline, NativeProof: *nativeProof, NativeBinary: *nativeBinary, ReplacementNativeProof: *replacementProof, GuestFixtures: name == "build-guest", Inspector: name == "build-inspector"})
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

func buildUpdateHost(repo string, args []string) int {
	flags := flag.NewFlagSet("build-update-host", flag.ContinueOnError)
	parent := flags.String("parent-registration", "", "registered normal update runtime")
	nativeBinary := flags.String("native-binary", "", "new qualified native binary")
	replacementProof := flags.String("replacement-native-proof", "", "native monitor proof of the new binary")
	out := flags.String("out", "", "new external output")
	verification := flags.String("verification", "", "shared verification root")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *parent == "" || *out == "" || (*nativeBinary == "") != (*replacementProof == "") {
		return 2
	}
	result, err := buildtools.BuildUpdateHost(context.Background(), buildtools.BuildOptions{Repository: repo, Verification: *verification, ParentRegistration: *parent, NativeBinary: *nativeBinary, ReplacementNativeProof: *replacementProof, Out: *out})
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
