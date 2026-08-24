package cicheck

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// repoRoot returns the repository root by walking up from the test file location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	// internal/cicheck/release_workflow_test.go -> repo root is two levels up
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// workflow is a minimal representation of a GitHub Actions workflow file.
type workflow struct {
	Name        string                 `yaml:"name"`
	On          map[string]any         `yaml:"on"`
	Permissions map[string]string      `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	RunsOn      string            `yaml:"runs-on"`
	TimeoutMin  int               `yaml:"timeout-minutes"`
	Needs       any               `yaml:"needs"`
	Permissions map[string]string `yaml:"permissions"`
	Strategy    *jobStrategy      `yaml:"strategy"`
	Steps       []workflowStep    `yaml:"steps"`
}

type jobStrategy struct {
	Matrix map[string]any `yaml:"matrix"`
}

type workflowStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

// loadWorkflow parses a workflow file from .github/workflows by name.
func loadWorkflow(t *testing.T, name string) workflow {
	t.Helper()
	path := filepath.Join(repoRoot(t), ".github", "workflows", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return wf
}

// releaseTarget is one entry of the build matrix that build.yml and release.yml
// share. ext is the binary's file extension, empty everywhere but Windows.
type releaseTarget struct{ goos, goarch, gomips, ext string }

// binary returns the file name the build step writes for this target, which is
// also the published release asset name.
func (rt releaseTarget) binary() string { return "plexd-" + rt.goos + "-" + rt.goarch + rt.ext }

// releaseTargets is the set of platforms every release ships. The Linux names
// are consumed by deploy/install.sh and internal/upgrade/fetcher.go, so they
// must not change.
var releaseTargets = []releaseTarget{
	{"linux", "amd64", "", ""},
	{"linux", "arm64", "", ""},
	{"linux", "mipsle", "softfloat", ""},
	{"windows", "amd64", "", ".exe"},
	{"windows", "arm64", "", ".exe"},
	{"darwin", "amd64", "", ""},
	{"darwin", "arm64", "", ""},
}

// matrixInclude returns a job's matrix.include entries keyed by "goos/goarch".
func matrixInclude(t *testing.T, job workflowJob) map[string]map[string]any {
	t.Helper()
	if job.Strategy == nil {
		t.Fatal("build job has no strategy")
	}
	includeRaw, ok := job.Strategy.Matrix["include"]
	if !ok {
		t.Fatal("build matrix missing include")
	}
	includeList, ok := includeRaw.([]any)
	if !ok {
		t.Fatalf("matrix.include is %T, want []any", includeRaw)
	}
	entries := make(map[string]map[string]any, len(includeList))
	for i, v := range includeList {
		entry, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("matrix.include[%d] is %T, want map", i, v)
		}
		goos, _ := entry["goos"].(string)
		goarch, _ := entry["goarch"].(string)
		if goos == "" || goarch == "" {
			t.Fatalf("matrix.include[%d] missing goos or goarch", i)
		}
		entries[goos+"/"+goarch] = entry
	}
	return entries
}

// assertBuildBinaryStep checks the cross-compilation step that build.yml and
// release.yml both carry. They differ only in the version ldflag.
func assertBuildBinaryStep(t *testing.T, steps []workflowStep, wantVersion string) {
	t.Helper()
	step, ok := findStep(steps, func(s workflowStep) bool {
		return s.Name == "Build binary"
	})
	if !ok {
		t.Fatal("missing Build binary step")
	}
	if step.Env["CGO_ENABLED"] != "0" {
		t.Error("CGO_ENABLED not set to 0")
	}
	for _, env := range []struct{ key, want string }{
		{"GOOS", "${{ matrix.goos }}"},
		{"GOARCH", "${{ matrix.goarch }}"},
		{"GOMIPS", "${{ matrix.gomips }}"},
	} {
		if got := step.Env[env.key]; got != env.want {
			t.Errorf("%s = %q, want %q (it must come from the matrix)", env.key, got, env.want)
		}
	}
	const wantOutput = "-o plexd-${{ matrix.goos }}-${{ matrix.goarch }}${{ matrix.ext }}"
	if !strings.Contains(step.Run, wantOutput) {
		t.Errorf("build step missing %q", wantOutput)
	}
	if !strings.Contains(step.Run, "-ldflags") {
		t.Error("missing -ldflags")
	}
	if !strings.Contains(step.Run, wantVersion) {
		t.Errorf("build step missing %q ldflag", wantVersion)
	}
}

func TestReleaseWorkflow_Name(t *testing.T) {
	wf := loadWorkflow(t, "release.yml")
	if wf.Name != "Release" {
		t.Errorf("workflow name = %q, want %q", wf.Name, "Release")
	}
}

func TestReleaseWorkflow_Trigger(t *testing.T) {
	wf := loadWorkflow(t, "release.yml")
	push, ok := wf.On["push"]
	if !ok {
		t.Fatal("missing on.push trigger")
	}
	pushMap, ok := push.(map[string]any)
	if !ok {
		t.Fatalf("on.push is %T, want map", push)
	}
	tags, ok := pushMap["tags"]
	if !ok {
		t.Fatal("missing on.push.tags")
	}
	tagList, ok := tags.([]any)
	if !ok {
		t.Fatalf("on.push.tags is %T, want []any", tags)
	}
	if len(tagList) == 0 {
		t.Fatal("on.push.tags is empty")
	}
	first, _ := tagList[0].(string)
	if first != "v*" {
		t.Errorf("first tag pattern = %q, want %q", first, "v*")
	}
}

func TestReleaseWorkflow_Permissions(t *testing.T) {
	wf := loadWorkflow(t, "release.yml")
	if wf.Permissions["contents"] != "write" {
		t.Errorf("permissions.contents = %q, want %q", wf.Permissions["contents"], "write")
	}
}

func TestReleaseWorkflow_BuildJob(t *testing.T) {
	wf := loadWorkflow(t, "release.yml")
	build, ok := wf.Jobs["build"]
	if !ok {
		t.Fatal("missing build job")
	}
	if build.RunsOn != "ubuntu-latest" {
		t.Errorf("build.runs-on = %q, want %q", build.RunsOn, "ubuntu-latest")
	}
	if build.TimeoutMin == 0 {
		t.Error("build.timeout-minutes not set")
	}
}

func TestReleaseWorkflow_BuildMatrix(t *testing.T) {
	wf := loadWorkflow(t, "release.yml")
	entries := matrixInclude(t, wf.Jobs["build"])

	if len(entries) != len(releaseTargets) {
		t.Errorf("matrix.include has %d entries, want %d", len(entries), len(releaseTargets))
	}
	for _, rt := range releaseTargets {
		key := rt.goos + "/" + rt.goarch
		entry, ok := entries[key]
		if !ok {
			t.Errorf("matrix.include missing target %q", key)
			continue
		}
		if gomips, _ := entry["gomips"].(string); gomips != rt.gomips {
			t.Errorf("%s gomips = %q, want %q", key, gomips, rt.gomips)
		}
		// ext carries the .exe suffix into the binary name, so a Windows entry
		// that loses it publishes an extensionless asset.
		if ext, _ := entry["ext"].(string); ext != rt.ext {
			t.Errorf("%s ext = %q, want %q", key, ext, rt.ext)
		}
	}
}

func findStep(steps []workflowStep, match func(workflowStep) bool) (workflowStep, bool) {
	for _, s := range steps {
		if match(s) {
			return s, true
		}
	}
	return workflowStep{}, false
}

func TestReleaseWorkflow_BuildSteps(t *testing.T) {
	wf := loadWorkflow(t, "release.yml")
	build := wf.Jobs["build"]

	t.Run("checkout pinned", func(t *testing.T) {
		step, ok := findStep(build.Steps, func(s workflowStep) bool {
			return strings.Contains(s.Uses, "actions/checkout@")
		})
		if !ok {
			t.Fatal("missing checkout step")
		}
		ref := strings.SplitN(step.Uses, "@", 2)[1]
		if len(ref) < 40 {
			t.Errorf("checkout not pinned to full SHA (ref=%q)", ref)
		}
	})

	t.Run("setup-go", func(t *testing.T) {
		if _, ok := findStep(build.Steps, func(s workflowStep) bool {
			return strings.Contains(s.Uses, "actions/setup-go@")
		}); !ok {
			t.Fatal("missing setup-go step")
		}
	})

	t.Run("build binary", func(t *testing.T) {
		assertBuildBinaryStep(t, build.Steps, "main.version=${GITHUB_REF_NAME}")
	})

	t.Run("checksum", func(t *testing.T) {
		step, ok := findStep(build.Steps, func(s workflowStep) bool {
			return s.Name == "Generate checksum"
		})
		if !ok {
			t.Fatal("missing Generate checksum step")
		}
		// The checksum line must name the binary exactly as it is published,
		// .exe included, so checksums.sha256 can be checked against the assets.
		const wantSum = "sha256sum plexd-${{ matrix.goos }}-${{ matrix.goarch }}${{ matrix.ext }}"
		if !strings.Contains(step.Run, wantSum) {
			t.Errorf("checksum step missing %q", wantSum)
		}
	})

	t.Run("upload-artifact", func(t *testing.T) {
		if _, ok := findStep(build.Steps, func(s workflowStep) bool {
			return strings.Contains(s.Uses, "actions/upload-artifact@")
		}); !ok {
			t.Fatal("missing upload-artifact step")
		}
	})
}

func TestReleaseWorkflow_ReleaseJob(t *testing.T) {
	wf := loadWorkflow(t, "release.yml")
	release, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("missing release job")
	}
	if release.RunsOn != "ubuntu-latest" {
		t.Errorf("release.runs-on = %q, want %q", release.RunsOn, "ubuntu-latest")
	}
	if release.TimeoutMin == 0 {
		t.Error("release.timeout-minutes not set")
	}

	// Verify needs: build
	switch v := release.Needs.(type) {
	case string:
		if v != "build" {
			t.Errorf("release.needs = %q, want %q", v, "build")
		}
	case []any:
		found := false
		for _, n := range v {
			if s, _ := n.(string); s == "build" {
				found = true
			}
		}
		if !found {
			t.Error("release.needs does not include build")
		}
	default:
		t.Fatalf("release.needs is %T, want string or []any", release.Needs)
	}
}

func TestReleaseWorkflow_ReleasePermissions(t *testing.T) {
	wf := loadWorkflow(t, "release.yml")
	release, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("missing release job")
	}
	// Keyless cosign signing needs an OIDC token, so the release job that
	// signs must request id-token: write in addition to contents: write.
	if release.Permissions["contents"] != "write" {
		t.Errorf("release permissions.contents = %q, want %q", release.Permissions["contents"], "write")
	}
	if release.Permissions["id-token"] != "write" {
		t.Errorf("release permissions.id-token = %q, want %q", release.Permissions["id-token"], "write")
	}
}

func TestReleaseWorkflow_ReleaseSteps(t *testing.T) {
	wf := loadWorkflow(t, "release.yml")
	release := wf.Jobs["release"]

	t.Run("download-artifact", func(t *testing.T) {
		if _, ok := findStep(release.Steps, func(s workflowStep) bool {
			return strings.Contains(s.Uses, "actions/download-artifact@")
		}); !ok {
			t.Fatal("missing download-artifact step")
		}
	})

	t.Run("combined checksums", func(t *testing.T) {
		step, ok := findStep(release.Steps, func(s workflowStep) bool {
			return s.Name == "Generate combined checksums"
		})
		if !ok {
			t.Fatal("missing Generate combined checksums step")
		}
		// The glob must cover every target, not just the Linux ones.
		const wantCat = "cat plexd-*.sha256 > checksums.sha256"
		if !strings.Contains(step.Run, wantCat) {
			t.Errorf("combined checksums step missing %q", wantCat)
		}
	})

	t.Run("cosign-installer", func(t *testing.T) {
		if _, ok := findStep(release.Steps, func(s workflowStep) bool {
			return strings.Contains(s.Uses, "sigstore/cosign-installer@")
		}); !ok {
			t.Fatal("missing cosign-installer step")
		}
	})

	t.Run("sign release binaries", func(t *testing.T) {
		step, ok := findStep(release.Steps, func(s workflowStep) bool {
			return strings.Contains(s.Run, "cosign sign-blob")
		})
		if !ok {
			t.Fatal("missing cosign sign-blob step")
		}
		if !strings.Contains(step.Run, "--bundle") {
			t.Error("cosign sign-blob step missing --bundle flag")
		}
		for _, rt := range releaseTargets {
			if !strings.Contains(step.Run, rt.binary()) {
				t.Errorf("cosign step does not sign %s", rt.binary())
			}
		}
	})

	t.Run("gh-release", func(t *testing.T) {
		step, ok := findStep(release.Steps, func(s workflowStep) bool {
			return strings.Contains(s.Uses, "softprops/action-gh-release@")
		})
		if !ok {
			t.Fatal("missing gh-release step")
		}
		files, _ := step.With["files"].(string)
		// Compare whole lines. "plexd-linux-amd64" is a substring of
		// "plexd-linux-amd64.sigstore.json", so a substring check would keep
		// passing after the binary itself was dropped from the list.
		listed := make(map[string]bool)
		for _, line := range strings.Split(files, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				listed[line] = true
			}
		}
		for _, rt := range releaseTargets {
			if !listed[rt.binary()] {
				t.Errorf("release files missing %s", rt.binary())
			}
			if bundle := rt.binary() + ".sigstore.json"; !listed[bundle] {
				t.Errorf("release files missing signature bundle %s", bundle)
			}
			if listed[rt.binary()+".sha256"] {
				t.Errorf("release files should not include per-binary %s.sha256", rt.binary())
			}
		}
		if !listed["checksums.sha256"] {
			t.Error("release files missing combined checksums.sha256")
		}
	})
}

func TestReleaseWorkflow_AllActionsPinned(t *testing.T) {
	assertAllActionsPinned(t, loadWorkflow(t, "release.yml"))
}

// assertAllActionsPinned rejects any `uses:` that is not pinned to a full
// commit SHA, the supply-chain rule this repository holds for every workflow.
func assertAllActionsPinned(t *testing.T, wf workflow) {
	t.Helper()
	for jobName, job := range wf.Jobs {
		for i, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			parts := strings.SplitN(step.Uses, "@", 2)
			if len(parts) != 2 {
				t.Errorf("job %s step %d: uses %q missing @ref", jobName, i, step.Uses)
				continue
			}
			ref := parts[1]
			// SHA refs are 40 hex chars; reject short tags like "v4"
			if len(ref) < 40 {
				t.Errorf("job %s step %d: action %q not pinned to full SHA (ref=%q)", jobName, i, parts[0], ref)
			}
		}
	}
}
