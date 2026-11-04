package hostvm

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

func (r *Runtime) updatePreparationRecoveryArgs(out string, req, prep Object) ([]string, error) {
	requestPath := filepath.Join(filepath.Dir(out), "request.json")
	root := filepath.Dir(filepath.Dir(filepath.Dir(out)))
	manifestPath := filepath.Join(root, "update-runtime.json")
	fixture := Str(req, "profile") == "filegate-update-fixture-v1" && req["fixture_only"] == true && Int(req, "schema") == 1
	if fixture {
		manifestPath = filepath.Join(root, "build/update-runtime.json")
	} else if Str(req, "profile") != "filegate-official-update-v1" || req["fixture_only"] != false || Int(req, "schema") != 2 || !validRequestPath(requestPath, "updates", "update_") {
		return nil, Error("PREPARATION_RECOVERY_SCOPE_INVALID")
	}
	canonical, err := filepath.EvalSymlinks(manifestPath)
	if err != nil || canonical != manifestPath {
		return nil, Error("PREPARATION_RECOVERY_MANIFEST_INVALID")
	}
	manifest, body, err := Read(manifestPath, 1<<20)
	if err != nil || HashBytes(body) != Str(req, "manifest_sha256") || Int(manifest, "schema") != 2 || Str(manifest, "workspace") != r.Root || Str(manifest, "profile") != Str(req, "profile") || manifest["fixture_only"] != req["fixture_only"] || Str(manifest, "library_sha256") != Str(req, "library_sha256") {
		return nil, Error("PREPARATION_RECOVERY_MANIFEST_CHANGED")
	}
	runner := Str(manifest, "runner")
	if runner != filepath.Join(r.Root, ".build/filegate-update") {
		return nil, Error("PREPARATION_RECOVERY_RUNNER_INVALID")
	}
	if _, err = Owned(runner, unix.S_IFREG, 0500); err != nil {
		return nil, err
	}
	pins := Map(manifest, "sha256")
	digest, err := HashFile(runner)
	if err != nil || !digestPattern.MatchString(Str(pins, runner)) || digest != Str(pins, runner) || len(pins) > 512 {
		return nil, Error("PREPARATION_RECOVERY_RUNNER_CHANGED")
	}
	if fixture {
		if !validFixturePreparation(manifestPath, requestPath, runner) {
			return nil, Error("PREPARATION_RECOVERY_FIXTURE_INVALID")
		}
	} else if !Fields(manifest, "schema", "profile", "fixture_only", "library_sha256", "workspace", "runner", "helper", "proof", "sha256", "engine", "adapter", "origin", "build", "adapter_manifest", "image_profile", "image_tools", "request_schema") || Int(manifest, "request_schema") != 2 || len(pins) < 16 {
		return nil, Error("PREPARATION_RECOVERY_MANIFEST_INVALID")
	}
	run := Str(prep, "run_directory")
	if !runPattern.MatchString(run) {
		return nil, Error("PREPARATION_RECOVERY_RUN_INVALID")
	}
	return []string{runner, "--prepare", "--manifest", manifestPath, "--request", requestPath, "--run-directory", run}, nil
}
