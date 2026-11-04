package buildtools

import (
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func BuildFreshclam(ctx context.Context, options BuildOptions) (result map[string]any, returned error) {
	repository, err := Repository(options.Repository)
	if err != nil {
		return nil, err
	}
	verification := options.Verification
	if verification == "" {
		verification, err = DefaultVerification()
		if err != nil {
			return nil, err
		}
	}
	rootfs := filepath.Join(verification, "experiments/vm/.cache/alpine-minirootfs-3.24.3-aarch64.tar.gz")
	manifestPath := filepath.Join(verification, "experiments/av/evidence/packages-build.json")
	packages := filepath.Join(verification, "experiments/av/cache/packages-build")
	manifest, err := object(manifestPath)
	if err != nil {
		return nil, err
	}
	rows, ok := manifest["packages"].([]any)
	if !ok || len(rows) != 109 || mustSHA(rootfs) != rootfsSHA {
		return nil, errors.New("fixed FreshClam compiler input mismatch")
	}
	pins := map[string]string{rootfs: rootfsSHA, manifestPath: mustSHA(manifestPath)}
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("compiler package row invalid")
		}
		name := str(row, "name") + "-" + str(row, "version") + ".apk"
		if !regexp.MustCompile(`^[A-Za-z0-9_.+~-]+\.apk$`).MatchString(name) {
			return nil, errors.New("compiler package name rejected")
		}
		path := filepath.Join(packages, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != number(row, "bytes") || mustSHA(path) != str(row, "sha256") {
			return nil, errors.New("compiler package digest changed")
		}
		pins[path] = str(row, "sha256")
	}
	selected, compilerInputs, err := compilerSubset(ctx, packages, rows)
	if err != nil {
		return nil, err
	}
	if options.CheckInputs {
		_, diagnostics, err := diagnosticCompilerSubset(ctx, packages, rows)
		if err != nil {
			return nil, err
		}
		return map[string]any{"checked": true, "container_started": false, "input_pins_sha256": pins, "compiler_dependency_closure": compilerInputs, "scan_diagnostic_dependency_closure": diagnostics}, nil
	}
	out, err := canonical(options.Out)
	if err != nil {
		return nil, err
	}
	if within(out, repository) {
		return nil, errors.New("new external FreshClam output required")
	}
	if _, err = os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("new FreshClam output required")
	}
	endpointBody, _, err := command(ctx, "", nil, "docker", "context", "inspect", "orbstack", "--format", "{{.Endpoints.docker.Host}}")
	if err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimSpace(string(endpointBody))
	if endpoint != "unix://"+filepath.Join(home, ".orbstack/run/docker.sock") {
		return nil, errors.New("fixed local Docker endpoint required")
	}
	socketInfo, err := os.Stat(strings.TrimPrefix(endpoint, "unix://"))
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("local Docker socket required")
	}
	if err = requireToolchain(ctx); err != nil {
		return nil, err
	}
	gorootBody, _, err := command(ctx, "", nil, "go", "env", "GOROOT")
	if err != nil {
		return nil, err
	}
	goroot, err := filepath.EvalSymlinks(strings.TrimSpace(string(gorootBody)))
	if err != nil {
		return nil, err
	}
	before, err := freshclamSources(repository)
	if err != nil {
		return nil, err
	}
	if err = os.Mkdir(out, 0700); err != nil {
		return nil, err
	}
	selectedPackages := filepath.Join(out, "compiler-packages")
	if err = os.Mkdir(selectedPackages, 0700); err != nil {
		return nil, err
	}
	apk := []string{}
	for _, name := range selected {
		if err = copyNew(filepath.Join(packages, name), filepath.Join(selectedPackages, name), 0444); err != nil {
			return nil, err
		}
		apk = append(apk, "/packages/"+name)
	}
	source := filepath.Join(out, "source")
	temporary := filepath.Join(out, "go-tmp")
	if err = os.Mkdir(temporary, 0700); err != nil {
		return nil, err
	}
	for name, expected := range before {
		target := filepath.Join(source, name)
		if err = copyNew(filepath.Join(repository, name), target, 0600); err != nil || mustSHA(target) != expected {
			return nil, errors.New("FreshClam source snapshot mismatch")
		}
	}
	record := map[string]any{"schema": 1, "target": "linux/arm64", "libc": "musl", "passed": false, "sources_sha256": before, "input_pins_sha256": pins, "build_toolchain": map[string]any{"version": hostGo, "go_sha256": mustSHA(filepath.Join(goroot, "bin/go"))}, "network": "none", "fixed_library_rebuilt": false, "implementation": "go", "python_dependency": false}
	record["compiler_dependency_closure"] = compilerInputs
	builderExecutable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	builderExecutable, err = filepath.EvalSymlinks(builderExecutable)
	if err != nil {
		return nil, err
	}
	record["builder_binary_sha256"] = mustSHA(builderExecutable)
	commands := []CommandRecord{}
	commandOutput := filepath.Join(out, "command-output")
	if err = os.Mkdir(commandOutput, 0700); err != nil {
		return nil, err
	}
	docker := []string{"docker", "--host", endpoint}
	buildContext, cancel := context.WithTimeout(ctx, 480*time.Second)
	defer cancel()
	image, container := "", ""
	success := false
	cleanedContainer, cleanedImage := false, false
	control := func(cleanup bool, timeout time.Duration, arguments ...string) (string, error) {
		parent := buildContext
		if cleanup {
			parent = context.Background()
		}
		controlCtx, stop := context.WithTimeout(parent, timeout)
		defer stop()
		cmd := exec.CommandContext(controlCtx, arguments[0], arguments[1:]...)
		stdout, stderr := &limitedBuffer{limit: 1 << 20}, &limitedBuffer{limit: 1 << 20}
		cmd.Stdout, cmd.Stderr = stdout, stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			code = 1
			var exited *exec.ExitError
			if errors.As(err, &exited) {
				code = exited.ExitCode()
			}
		}
		stdoutPath := filepath.Join(commandOutput, fmt.Sprintf("%03d.stdout", len(commands)+1))
		stderrPath := filepath.Join(commandOutput, fmt.Sprintf("%03d.stderr", len(commands)+1))
		for path, body := range map[string][]byte{stdoutPath: stdout.body, stderrPath: stderr.body} {
			if err := os.WriteFile(path, body, 0600); err != nil {
				return "", err
			}
		}
		commands = append(commands, CommandRecord{Argv: arguments, ExitCode: code, StdoutBytes: len(stdout.body), StderrBytes: len(stderr.body), StdoutArtifact: stdoutPath, StderrArtifact: stderrPath, StdoutSHA256: digest(stdout.body), StderrSHA256: digest(stderr.body), Truncated: stdout.exceeded || stderr.exceeded})
		if err != nil || stdout.exceeded || stderr.exceeded {
			diagnostic := strings.TrimSpace(string(stderr.body))
			if len(diagnostic) > 512 {
				diagnostic = diagnostic[:512] + "..."
			}
			return "", fmt.Errorf("owned build control failed (exit %d, stderr %s): %s", code, stderrPath, diagnostic)
		}
		return strings.TrimSpace(string(stdout.body)), nil
	}
	defer func() {
		if container != "" {
			_, stopErr := control(true, 20*time.Second, append(docker, "stop", "--time", "2", container)...)
			if stopErr == nil {
				running, e := control(true, 10*time.Second, append(docker, "inspect", "--type", "container", "--format", "{{.State.Running}}", container)...)
				if e == nil && running == "false" {
					record["container_stopped"] = true
					_, e = control(true, 20*time.Second, append(docker, "rm", container)...)
					if e == nil {
						cleanedContainer = true
						record["container_removed"] = true
					}
				}
			}
		}
		if image != "" && (container == "" || cleanedContainer) {
			if _, e := control(true, 20*time.Second, append(docker, "image", "rm", image)...); e == nil {
				cleanedImage = true
				record["imported_image_removed"] = true
			}
		}
		after, sourceErr := freshclamSources(repository)
		unchanged := sourceErr == nil && equalStringMaps(before, after)
		pinErr := verifyPins(pins)
		record["sources_sha256_after"] = after
		record["sources_unchanged"] = unchanged
		record["input_pins_unchanged"] = pinErr == nil
		record["owned_go_process_exited"] = true
		record["commands"] = commands
		record["passed"] = success && unchanged && pinErr == nil && cleanedContainer && cleanedImage
		if returned != nil {
			record["error"] = returned.Error()
		}
		if saveErr := saveNewJSON(filepath.Join(out, "build.json"), record); saveErr != nil && returned == nil {
			returned = saveErr
		}
		if record["passed"] != true && returned == nil {
			returned = errors.New("FreshClam construction or cleanup did not pass")
		}
		result = map[string]any{"passed": record["passed"], "receipt": filepath.Join(out, "build.json"), "error": record["error"]}
	}()
	image, err = control(false, time.Minute, append(docker, "import", "--platform", "linux/arm64", rootfs)...)
	if err != nil {
		return nil, err
	}
	if !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(image) {
		return nil, errors.New("owned image identity invalid")
	}
	identifier := make([]byte, 16)
	if _, err = rand.Read(identifier); err != nil {
		return nil, err
	}
	create := append(append([]string{}, docker...), "create", "--name", "filegate-go-freshclam-"+hex.EncodeToString(identifier), "--platform", "linux/arm64", "--pull", "never", "--network", "none", "--cpus", "2", "--memory", "4294967296", "--memory-swap", "4294967296", "--pids-limit", "256", "--log-driver", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--stop-timeout", "2")
	for _, capability := range []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"} {
		create = append(create, "--cap-add", capability)
	}
	for _, mount := range []struct {
		from, to string
		readonly bool
	}{{selectedPackages, "/packages", true}, {out, out, false}, {source, source, true}, {goroot, goroot, true}} {
		value := "type=bind,source=" + mount.from + ",target=" + mount.to
		if mount.readonly {
			value += ",readonly"
		}
		create = append(create, "--mount", value)
	}
	create = append(create, image, "/bin/sleep", "480")
	container, err = control(false, time.Minute, create...)
	if err != nil {
		return nil, err
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(container) {
		return nil, errors.New("owned container identity invalid")
	}
	if err = saveNewJSON(filepath.Join(out, "owned-container.json"), map[string]string{"container_id": container, "image_id": image, "endpoint": endpoint}); err != nil {
		return nil, err
	}
	if _, err = control(false, time.Minute, append(docker, "start", container)...); err != nil {
		return nil, err
	}
	limitsText, err := control(false, 10*time.Second, append(docker, "inspect", "--type", "container", "--format", `{"memory":{{.HostConfig.Memory}},"swap":{{.HostConfig.MemorySwap}},"cpus":{{.HostConfig.NanoCpus}},"network":{{json .HostConfig.NetworkMode}},"log":{{json .HostConfig.LogConfig.Type}}}`, container)...)
	if err != nil {
		return nil, err
	}
	limits := map[string]any{}
	if json.Unmarshal([]byte(limitsText), &limits) != nil || number(limits, "memory") != 4<<30 || number(limits, "swap") != 4<<30 || number(limits, "cpus") != 2000000000 || str(limits, "network") != "none" || str(limits, "log") != "none" {
		return nil, errors.New("owned compiler limits mismatch")
	}
	record["limits"] = limits
	if _, err = control(false, 120*time.Second, append(append(append([]string{}, docker...), "exec", container, "/sbin/apk", "add", "--no-network"), apk...)...); err != nil {
		return nil, err
	}
	compiler, err := control(false, 10*time.Second, append(docker, "exec", container, "/usr/bin/gcc", "--version")...)
	if err != nil {
		return nil, err
	}
	compilerRecord := map[string]string{"version": compiler}
	for _, value := range rows {
		row := value.(map[string]any)
		for _, name := range []string{"gcc", "musl", "musl-dev"} {
			if str(row, "name") == name {
				compilerRecord[name+"_apk_sha256"] = str(row, "sha256")
			}
		}
	}
	record["compiler"] = compilerRecord
	wrapperSource := filepath.Join(out, "cc.go")
	wrapper := filepath.Join(out, "cc-wrapper")
	body := fmt.Sprintf("package main\nimport (\"os\";\"os/exec\")\nfunc main(){cwd,e:=os.Getwd();if e!=nil{os.Exit(1)};argv:=[]string{\"--host\",%q,\"exec\",\"-i\",\"--workdir\",cwd,%q,\"/usr/bin/gcc\"};argv=append(argv,os.Args[1:]...);c:=exec.Command(\"docker\",argv...);c.Stdin=os.Stdin;c.Stdout=os.Stdout;c.Stderr=os.Stderr;if e=c.Run();e!=nil{if v,ok:=e.(*exec.ExitError);ok{os.Exit(v.ExitCode())};os.Exit(1)}}\n", endpoint, container)
	if err = os.WriteFile(wrapperSource, []byte(body), 0600); err != nil {
		return nil, err
	}
	if _, _, err = command(buildContext, out, goEnvironment("darwin"), "go", "build", "-trimpath", "-o", wrapper, wrapperSource); err != nil {
		return nil, err
	}
	if err = os.Chmod(wrapper, 0500); err != nil {
		return nil, err
	}
	record["cc_wrapper_source_sha256"] = mustSHA(wrapperSource)
	record["cc_wrapper_sha256"] = mustSHA(wrapper)
	binary := filepath.Join(out, "filegate-freshclam")
	buildArgs := []string{"go", "build", "-trimpath", "-o", binary, "./cmd/filegate-freshclam"}
	record["build_command"] = buildArgs
	commandEnvironment := environment(map[string]string{"GOPROXY": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly", "GOOS": "linux", "GOARCH": "arm64", "GOARM64": "v8.0", "CGO_ENABLED": "1", "CC": shellQuote(wrapper), "GOTMPDIR": temporary, "TMPDIR": temporary})
	cmd := exec.CommandContext(buildContext, buildArgs[0], buildArgs[1:]...)
	cmd.Dir = source
	cmd.Env = commandEnvironment
	cmd.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	stdout, err := os.OpenFile(filepath.Join(out, "build.stdout"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	stderr, err := os.OpenFile(filepath.Join(out, "build.stderr"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		stdout.Close()
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	stdout.Close()
	stderr.Close()
	if err != nil {
		return nil, fmt.Errorf("Go/cgo build failed: %w", err)
	}
	record["build_exit_code"] = 0
	file, err := elf.Open(binary)
	if err != nil {
		return nil, err
	}
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_AARCH64 {
		file.Close()
		return nil, errors.New("built ELF target mismatch")
	}
	interpreters := []string{}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			value, e := io.ReadAll(io.LimitReader(program.Open(), 4097))
			if e != nil {
				file.Close()
				return nil, e
			}
			interpreters = append(interpreters, strings.TrimRight(string(value), "\x00"))
		}
	}
	file.Close()
	if len(interpreters) != 1 || interpreters[0] != "/lib/ld-musl-aarch64.so.1" {
		return nil, errors.New("built ELF musl interpreter mismatch")
	}
	record["elf"] = map[string]any{"machine": "AArch64", "class": 64, "interpreter": interpreters[0]}
	record["binary_sha256"] = mustSHA(binary)
	invalid := exec.CommandContext(buildContext, "docker", "--host", endpoint, "exec", container, binary, "--invalid")
	var invalidOut, invalidErr strings.Builder
	invalid.Stdout, invalid.Stderr = &invalidOut, &invalidErr
	err = invalid.Run()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 1 || invalidErr.Len() != 0 {
		return nil, errors.New("built adapter invalid-argument behavior mismatch")
	}
	report := map[string]any{}
	if json.Unmarshal([]byte(invalidOut.String()), &report) != nil || len(report) != 5 || number(report, "schema_version") != 1 || report["final"] != false || report["control_complete"] != false || report["control_snapshot"] != nil || str(report, "reason_code") != "UPDATE_STATE_UNKNOWN" {
		return nil, errors.New("built adapter invalid-argument report mismatch")
	}
	record["linux_invalid_argument"] = map[string]any{"exit_code": 1, "stdout_sha256": digest([]byte(invalidOut.String())), "stderr_bytes": 0, "report": report}
	success = true
	return nil, nil
}

func equalStringMaps(one, two map[string]string) bool {
	if len(one) != len(two) {
		return false
	}
	for key, value := range one {
		if two[key] != value {
			return false
		}
	}
	return true
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

type limitedBuffer struct {
	body     []byte
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(body []byte) (int, error) {
	size := len(body)
	if len(b.body)+size > b.limit {
		b.exceeded = true
		keep := b.limit - len(b.body)
		if keep > 0 {
			b.body = append(b.body, body[:keep]...)
		}
		return size, nil
	}
	b.body = append(b.body, body...)
	return size, nil
}
