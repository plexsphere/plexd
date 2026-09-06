package cicheck

import (
	"strings"
	"testing"
)

// docsPagesSteps are the two steps of the build job that exist only to publish:
// everything else in that job is the build a pull request wants.
var docsPagesSteps = []string{"configure-pages", "upload-pages-artifact"}

// TestDocsWorkflow_BuildsOnPullRequest pins the trigger that makes the docs
// build a pre-merge check. Without it the site is built only after a merge,
// and a dead link is found once it has already broken the published page.
func TestDocsWorkflow_BuildsOnPullRequest(t *testing.T) {
	wf := loadWorkflow(t, "docs.yml")

	pr, ok := wf.On["pull_request"]
	if !ok {
		t.Fatal("missing on.pull_request trigger")
	}
	prMap, ok := pr.(map[string]any)
	if !ok {
		t.Fatalf("on.pull_request is %T, want map", pr)
	}
	paths, ok := prMap["paths"]
	if !ok {
		t.Fatal("missing on.pull_request.paths")
	}
	pathList, ok := paths.([]any)
	if !ok {
		t.Fatalf("on.pull_request.paths is %T, want []any", paths)
	}

	// npm ci reads package-lock.json, so a change to it can break the build
	// without touching a single page.
	for _, want := range []string{"docs/**", "package.json", "package-lock.json"} {
		found := false
		for _, p := range pathList {
			if s, _ := p.(string); s == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("on.pull_request.paths missing %q", want)
		}
	}
}

func TestDocsWorkflow_BuildStep(t *testing.T) {
	wf := loadWorkflow(t, "docs.yml")
	build, ok := wf.Jobs["build"]
	if !ok {
		t.Fatal("missing build job")
	}

	step, ok := findStep(build.Steps, func(s workflowStep) bool {
		return strings.Contains(s.Run, "npm run docs:build")
	})
	if !ok {
		t.Fatal("build job never runs npm run docs:build")
	}
	// The build itself must run on a pull request; only publishing is gated.
	if step.If != "" {
		t.Errorf("the docs build is conditional on %q, so a pull request would skip the check", step.If)
	}

	if _, ok := findStep(build.Steps, func(s workflowStep) bool {
		return strings.Contains(s.Run, "npm ci")
	}); !ok {
		t.Error("build job never runs npm ci")
	}
}

// TestDocsWorkflow_DeployOnlyOnPush proves a pull request cannot publish. The
// workflow holds pages: write and id-token: write, so the guard on the deploy
// job and on the two Pages steps is what keeps a branch build from replacing
// the live site.
func TestDocsWorkflow_DeployOnlyOnPush(t *testing.T) {
	wf := loadWorkflow(t, "docs.yml")

	deploy, ok := wf.Jobs["deploy"]
	if !ok {
		t.Fatal("missing deploy job")
	}
	if !strings.Contains(deploy.If, "pull_request") {
		t.Errorf("deploy job if = %q, want it to exclude pull requests", deploy.If)
	}

	build := wf.Jobs["build"]
	for _, want := range docsPagesSteps {
		step, ok := findStep(build.Steps, func(s workflowStep) bool {
			return strings.Contains(s.Uses, want)
		})
		if !ok {
			t.Errorf("build job has no %s step", want)
			continue
		}
		if !strings.Contains(step.If, "pull_request") {
			t.Errorf("%s step if = %q, want it to exclude pull requests", want, step.If)
		}
	}
}

func TestDocsWorkflow_AllActionsPinned(t *testing.T) {
	assertAllActionsPinned(t, loadWorkflow(t, "docs.yml"))
}
