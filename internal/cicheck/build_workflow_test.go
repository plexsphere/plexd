package cicheck

import (
	"reflect"
	"testing"
)

// TestBuildWorkflow_MatrixMatchesRelease pins build.yml's matrix to release.yml's.
// build.yml runs on every pull request and is the only pre-merge proof that a
// target still cross-compiles; release.yml runs on tags, where a target that
// stopped building is found once the release is already going out. A platform
// added to one file and not the other is the drift this catches.
func TestBuildWorkflow_MatrixMatchesRelease(t *testing.T) {
	build := matrixInclude(t, loadWorkflow(t, "build.yml").Jobs["build"])
	release := matrixInclude(t, loadWorkflow(t, "release.yml").Jobs["build"])

	if !reflect.DeepEqual(build, release) {
		t.Errorf("build.yml matrix differs from release.yml\nbuild.yml:   %v\nrelease.yml: %v", build, release)
	}
}

func TestBuildWorkflow_BuildStep(t *testing.T) {
	build, ok := loadWorkflow(t, "build.yml").Jobs["build"]
	if !ok {
		t.Fatal("missing build job")
	}
	// build.yml stamps a fixed version; release.yml stamps the tag.
	assertBuildBinaryStep(t, build.Steps, "main.version=dev")
}

func TestBuildWorkflow_AllActionsPinned(t *testing.T) {
	assertAllActionsPinned(t, loadWorkflow(t, "build.yml"))
}
