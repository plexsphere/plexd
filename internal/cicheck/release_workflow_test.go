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

func loadReleaseWorkflow(t *testing.T) workflow {
	t.Helper()
	path := filepath.Join(repoRoot(t), ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	return wf
}

func TestReleaseWorkflow_Name(t *testing.T) {
	wf := loadReleaseWorkflow(t)
	if wf.Name != "Release" {
		t.Errorf("workflow name = %q, want %q", wf.Name, "Release")
	}
}

func TestReleaseWorkflow_Trigger(t *testing.T) {
	wf := loadReleaseWorkflow(t)
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
	wf := loadReleaseWorkflow(t)
	if wf.Permissions["contents"] != "write" {
		t.Errorf("permissions.contents = %q, want %q", wf.Permissions["contents"], "write")
	}
}

func TestReleaseWorkflow_BuildJob(t *testing.T) {
	wf := loadReleaseWorkflow(t)
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
	wf := loadReleaseWorkflow(t)
	build := wf.Jobs["build"]
	if build.Strategy == nil {
		t.Fatal("build job has no strategy")
	}
	includeRaw, ok := build.Strategy.Matrix["include"]
	if !ok {
		t.Fatal("build matrix missing include")
	}
	includeList, ok := includeRaw.([]any)
	if !ok {
		t.Fatalf("matrix.include is %T, want []any", includeRaw)
	}
	arches := make(map[string]map[string]any)
	for i, v := range includeList {
		entry, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("matrix.include[%d] is %T, want map", i, v)
		}
		goarch, _ := entry["goarch"].(string)
		if goarch == "" {
			t.Fatalf("matrix.include[%d] missing goarch", i)
		}
		arches[goarch] = entry
	}
	for _, want := range []string{"amd64", "arm64", "mipsle"} {
		if _, ok := arches[want]; !ok {
			t.Errorf("matrix.include missing goarch %q", want)
		}
	}
	if mipsle, ok := arches["mipsle"]; ok {
		if gomips, _ := mipsle["gomips"].(string); gomips != "softfloat" {
			t.Errorf("mipsle gomips = %q, want %q", gomips, "softfloat")
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
	wf := loadReleaseWorkflow(t)
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
		step, ok := findStep(build.Steps, func(s workflowStep) bool {
			return s.Name == "Build binary"
		})
		if !ok {
			t.Fatal("missing Build binary step")
		}
		if step.Env["CGO_ENABLED"] != "0" {
			t.Error("CGO_ENABLED not set to 0")
		}
		if step.Env["GOOS"] != "linux" {
			t.Error("GOOS not set to linux")
		}
		if !strings.Contains(step.Run, "-ldflags") {
			t.Error("missing -ldflags")
		}
		if !strings.Contains(step.Run, "main.version") {
			t.Error("missing main.version ldflags")
		}
	})

	t.Run("checksum", func(t *testing.T) {
		step, ok := findStep(build.Steps, func(s workflowStep) bool {
			return s.Name == "Generate checksum"
		})
		if !ok {
			t.Fatal("missing Generate checksum step")
		}
		if !strings.Contains(step.Run, "sha256sum") {
			t.Error("missing sha256sum command")
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
	wf := loadReleaseWorkflow(t)
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
	wf := loadReleaseWorkflow(t)
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
	wf := loadReleaseWorkflow(t)
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
		if !strings.Contains(step.Run, "checksums.sha256") {
			t.Error("missing checksums.sha256 output")
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
	})

	t.Run("gh-release", func(t *testing.T) {
		step, ok := findStep(release.Steps, func(s workflowStep) bool {
			return strings.Contains(s.Uses, "softprops/action-gh-release@")
		})
		if !ok {
			t.Fatal("missing gh-release step")
		}
		files, _ := step.With["files"].(string)
		for _, arch := range []string{"amd64", "arm64", "mipsle"} {
			binary := "plexd-linux-" + arch
			if !strings.Contains(files, binary) {
				t.Errorf("release files missing %s", binary)
			}
			if strings.Contains(files, binary+".sha256") {
				t.Errorf("release files should not include per-binary %s.sha256", binary)
			}
			bundle := binary + ".sigstore.json"
			if !strings.Contains(files, bundle) {
				t.Errorf("release files missing signature bundle %s", bundle)
			}
		}
		if !strings.Contains(files, "checksums.sha256") {
			t.Error("release files missing combined checksums.sha256")
		}
	})
}

func TestReleaseWorkflow_AllActionsPinned(t *testing.T) {
	wf := loadReleaseWorkflow(t)
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
