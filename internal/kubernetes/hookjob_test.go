package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/actions"
)

// logRecord is one record a logRecorder kept, with its attributes and those of
// the logger it came through as strings.
type logRecord struct {
	level   slog.Level
	message string
	attrs   map[string]string
}

// logRecorder keeps every record of the loggers it hands out.
type logRecorder struct {
	mu      sync.Mutex
	records []logRecord
}

func (l *logRecorder) logger() *slog.Logger { return slog.New(&recordingHandler{rec: l}) }

// find returns the records at level with message.
func (l *logRecorder) find(level slog.Level, message string) []logRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []logRecord
	for _, r := range l.records {
		if r.level == level && r.message == message {
			out = append(out, r)
		}
	}
	return out
}

// warnings returns the messages of every warning, in order.
func (l *logRecorder) warnings() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, r := range l.records {
		if r.level == slog.LevelWarn {
			out = append(out, r.message)
		}
	}
	return out
}

type recordingHandler struct {
	rec   *logRecorder
	attrs []slog.Attr
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := make(map[string]string, len(h.attrs)+r.NumAttrs())
	for _, a := range h.attrs {
		attrs[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	h.rec.mu.Lock()
	h.rec.records = append(h.rec.records, logRecord{level: r.Level, message: r.Message, attrs: attrs})
	h.rec.mu.Unlock()
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &recordingHandler{rec: h.rec, attrs: append(slices.Clip(h.attrs), attrs...)}
}

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

// fakeHookJobAPI stands in for JobClient. Every method records its name in
// calls and fails the test when it is not called in testNamespace or without a
// deadline on its context. ListJobPods, PodLog and DeleteJob fail with their
// context's error once it has ended, as JobClient's calls do.
type fakeHookJobAPI struct {
	t *testing.T

	mu    sync.Mutex
	calls []string

	hook    *PlexdHook
	hookErr error

	createErr error
	created   []*HookJob

	// getJob answers the nth GetJob call, counted from 1.
	getJob      func(ctx context.Context, n int) (JobState, error)
	getJobCalls int
	getJobNames []string

	pods    []JobPod
	listErr error
	// beforeList runs at the start of every ListJobPods call, outside the
	// lock, so a test can end a context while the runner reads a pod list.
	beforeList func()

	logs      map[string]string // by pod name
	logErr    error
	logLimits []int64
	logPods   []string
	// logBlocks has PodLog wait for its context to end and return its error,
	// as a log read of an API server that does not answer does.
	logBlocks bool

	deleteErr error
	deleted   []string

	// deadlines holds, per call, how long its context had left when it came
	// in.
	deadlines []time.Duration
}

const testNamespace = "plexd-system"

func (f *fakeHookJobAPI) record(ctx context.Context, method, namespace string) {
	f.t.Helper()
	f.calls = append(f.calls, method)
	if namespace != testNamespace {
		f.t.Errorf("%s in namespace %q, want %q", method, namespace, testNamespace)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		f.t.Errorf("%s context has no deadline", method)
		return
	}
	f.deadlines = append(f.deadlines, time.Until(deadline))
}

func (f *fakeHookJobAPI) GetPlexdHook(ctx context.Context, namespace, name string) (*PlexdHook, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(ctx, "GetPlexdHook", namespace)
	if f.hookErr != nil {
		return nil, f.hookErr
	}
	if f.hook == nil || f.hook.Name != name {
		return nil, fmt.Errorf("kubernetes: get plexdhook %q: status 404: %w", name, ErrNotFound)
	}
	hook := *f.hook
	return &hook, nil
}

func (f *fakeHookJobAPI) CreateJob(ctx context.Context, namespace string, job *HookJob) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(ctx, "CreateJob", namespace)
	f.created = append(f.created, job)
	return f.createErr
}

func (f *fakeHookJobAPI) GetJob(ctx context.Context, namespace, name string) (JobState, error) {
	f.mu.Lock()
	f.record(ctx, "GetJob", namespace)
	f.getJobCalls++
	n := f.getJobCalls
	f.getJobNames = append(f.getJobNames, name)
	getJob := f.getJob
	f.mu.Unlock()
	if getJob == nil {
		return JobState{}, nil
	}
	return getJob(ctx, n)
}

func (f *fakeHookJobAPI) DeleteJob(ctx context.Context, namespace, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(ctx, "DeleteJob", namespace)
	if err := ctx.Err(); err != nil {
		return err
	}
	f.deleted = append(f.deleted, name)
	return f.deleteErr
}

func (f *fakeHookJobAPI) ListJobPods(ctx context.Context, namespace, jobName string) ([]JobPod, error) {
	if f.beforeList != nil {
		f.beforeList()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(ctx, "ListJobPods", namespace)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if jobName != hookJobName(testNodeID, testExecutionID) {
		f.t.Errorf("ListJobPods of %q, want the run's Job", jobName)
	}
	if f.listErr != nil {
		return nil, f.listErr
	}
	return slices.Clone(f.pods), nil
}

func (f *fakeHookJobAPI) PodLog(ctx context.Context, namespace, pod string, limitBytes int64) (string, error) {
	f.mu.Lock()
	f.record(ctx, "PodLog", namespace)
	f.logPods = append(f.logPods, pod)
	f.logLimits = append(f.logLimits, limitBytes)
	blocks, logErr, log := f.logBlocks, f.logErr, f.logs[pod]
	f.mu.Unlock()
	if blocks {
		<-ctx.Done()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if logErr != nil {
		return "", logErr
	}
	return log, nil
}

// callsSnapshot returns the calls made so far.
func (f *fakeHookJobAPI) callsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// count returns how often method was called.
func (f *fakeHookJobAPI) count(method string) int {
	n := 0
	for _, c := range f.callsSnapshot() {
		if c == method {
			n++
		}
	}
	return n
}

const (
	testNodeID      = "node-a"
	testExecutionID = "exec-1"
	testNodeName    = "kind-worker"
	testOutputLimit = 1024
	testHookImage   = "registry.example/backup@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	testHookUID     = "5b9e2a7c-3f1d-4c2e-9a8b-0c1d2e3f4a5b"
)

// testPlexdHook is a PlexdHook pinned by digest, with one parameter.
func testPlexdHook() *PlexdHook {
	return &PlexdHook{
		Name:      "nightly-backup",
		Namespace: testNamespace,
		UID:       testHookUID,
		Spec: PlexdHookSpec{
			HookName: "backup",
			JobTemplate: &PlexdHookJobTemplate{
				Image:   testHookImage,
				Command: []string{"/bin/backup"},
				Args:    []string{"--full"},
			},
			Parameters: []PlexdHookParam{{Name: "retention", Value: "7d"}},
		},
	}
}

// newTestHookJobRunner is a runner over api for node testNodeID on
// testNodeName, polling every millisecond.
func newTestHookJobRunner(t *testing.T, api *fakeHookJobAPI) (*HookJobRunner, *logRecorder) {
	t.Helper()
	api.t = t
	logs := &logRecorder{}
	r := NewHookJobRunner(api, HookJobConfig{
		Namespace:   testNamespace,
		NodeName:    testNodeName,
		NodeID:      testNodeID,
		OutputLimit: testOutputLimit,
	}, logs.logger())
	r.pollInterval = time.Millisecond
	return r, logs
}

// testRun is a dispatch of testPlexdHook.
func testRun(deadline time.Duration, params map[string]string) actions.PlexdHookRun {
	if params == nil {
		params = map[string]string{}
	}
	return actions.PlexdHookRun{
		ExecutionID: testExecutionID,
		Hook:        "nightly-backup",
		Parameters:  params,
		Deadline:    deadline,
	}
}

func intPtr(v int) *int { return &v }

// waitLimit only turns a Wait that never returns into a failure instead of a
// hung test.
const waitLimit = 30 * time.Second

// waitCtx is a context for a Wait that should return well before waitLimit.
func waitCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitLimit)
	t.Cleanup(cancel)
	return ctx
}

func TestHookJobName(t *testing.T) {
	a := hookJobName("node-a", "exec-1")
	b := hookJobName("node-b", "exec-1")
	// The values are written out, so a change to the derivation shows up here.
	if a != "plexdhook-078a49b48bea93928ef8732ddf0981db" {
		t.Errorf("hookJobName(node-a, exec-1) = %q", a)
	}
	if b != "plexdhook-3fd4f03ba17c8d4dbd3078d645c67197" {
		t.Errorf("hookJobName(node-b, exec-1) = %q", b)
	}
	if a == b {
		t.Errorf("two nodes share the Job name %q for one execution", a)
	}
	for _, name := range []string{a, b} {
		if len(name) != 42 {
			t.Errorf("len(%q) = %d, want 42", name, len(name))
		}
	}

	// The zero byte keeps the boundary between the two ids.
	if hookJobName("node-a", "bexec") == hookJobName("node-ab", "exec") {
		t.Error("moving a byte from the execution id to the node id kept the name")
	}

	dnsLabel := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	long := strings.Repeat("Exec/ID_", 38)[:300]
	name := hookJobName("Node/ID", long)
	if !dnsLabel.MatchString(name) || len(name) > 63 {
		t.Errorf("hookJobName of a 300-byte id = %q, want a DNS label", name)
	}
}

func TestSanitizeHookParamName(t *testing.T) {
	for in, want := range map[string]string{
		"target":    "TARGET",
		"my-param":  "MY_PARAM",
		"disk.path": "DISK_PATH",
		"Already_1": "ALREADY_1",
		"größe":     "GR__E",
		"":          "",
	} {
		if got := sanitizeHookParamName(in); got != want {
			t.Errorf("sanitizeHookParamName(%q) = %q, want %q", in, got, want)
		}
	}
}

// hookJobDocument is the Job of boundary 7 for testPlexdHook dispatched as
// testRun, with the parts that depend on the case left to fill in.
const hookJobDocument = `{
  "apiVersion": "batch/v1",
  "kind": "Job",
  "metadata": {
    "name": "plexdhook-078a49b48bea93928ef8732ddf0981db",
    "labels": {"app.kubernetes.io/managed-by": "plexd"},
    "annotations": {
      "plexd.plexsphere.com/execution-id": "exec-1",
      "plexd.plexsphere.com/node-id": "node-a",
      "plexd.plexsphere.com/hook": "nightly-backup"
    },
    "ownerReferences": [{
      "apiVersion": "plexd.plexsphere.com/v1alpha1",
      "kind": "PlexdHook",
      "name": "nightly-backup",
      "uid": "5b9e2a7c-3f1d-4c2e-9a8b-0c1d2e3f4a5b",
      "controller": true,
      "blockOwnerDeletion": false
    }]
  },
  "spec": {
    "backoffLimit": 0,
    "activeDeadlineSeconds": %d,
    "ttlSecondsAfterFinished": 3600,
    "template": {
      "metadata": {"labels": {"app.kubernetes.io/managed-by": "plexd"}},
      "spec": {
        "restartPolicy": "Never",
        "automountServiceAccountToken": false,
        "tolerations": [{"operator": "Exists"}],
        "affinity": {
          "nodeAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": {
              "nodeSelectorTerms": [{
                "matchFields": [{"key": "metadata.name", "operator": "In", "values": ["kind-worker"]}]
              }]
            }
          }
        },
        "containers": [{
          "name": "hook",
          "image": "registry.example/backup@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          %s
          "env": [
            {"name": "PLEXD_EXECUTION_ID", "value": "exec-1"},
            {"name": "PLEXD_HOOK_NAME", "value": "backup"},
            {"name": "PLEXD_NODE_ID", "value": "node-a"},
            {"name": "PLEXD_PARAM_RETENTION", "value": "7d"}
          ],
          "securityContext": %s
        }]
      }
    }
  }
}`

// requireSameJSON fails the test unless got and want hold the same JSON value.
func requireSameJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var gotV, wantV any
	if err := json.Unmarshal(got, &gotV); err != nil {
		t.Fatalf("got is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &wantV); err != nil {
		t.Fatalf("want is not JSON: %v\n%s", err, want)
	}
	if !reflect.DeepEqual(gotV, wantV) {
		gotPretty, _ := json.MarshalIndent(gotV, "", "  ")
		wantPretty, _ := json.MarshalIndent(wantV, "", "  ")
		t.Fatalf("Job document differs\ngot:\n%s\nwant:\n%s", gotPretty, wantPretty)
	}
}

// The created Job is compared with the document of boundary 7 as a whole, so
// a key that is missing, extra or different fails. The pod carries no
// app.kubernetes.io/name, no ServiceAccount and no token.
func TestHookJobRunner_StartJobDocument(t *testing.T) {
	for _, tc := range []struct {
		name            string
		privileged      bool
		noCommand       bool
		deadline        time.Duration
		activeDeadline  int64
		deadlineSeconds string
		command         string
		securityContext string
	}{
		{
			name:            "unprivileged, 600s",
			deadline:        600 * time.Second,
			activeDeadline:  630,
			deadlineSeconds: "600",
			command:         `"command": ["/bin/backup"], "args": ["--full"],`,
			securityContext: `{"readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}}`,
		},
		{
			name:            "privileged, 1.2s, no command",
			privileged:      true,
			noCommand:       true,
			deadline:        1200 * time.Millisecond,
			activeDeadline:  32,
			deadlineSeconds: "2",
			securityContext: `{"privileged": true}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := testPlexdHook()
			hook.Spec.Privileged = tc.privileged
			if tc.noCommand {
				hook.Spec.JobTemplate.Command = nil
				hook.Spec.JobTemplate.Args = nil
			}
			api := &fakeHookJobAPI{hook: hook}
			r, logs := newTestHookJobRunner(t, api)

			if err := r.Start(context.Background(), testRun(tc.deadline, nil)); err != nil {
				t.Fatalf("Start: %v", err)
			}

			if got := api.callsSnapshot(); !slices.Equal(got, []string{"GetPlexdHook", "CreateJob"}) {
				t.Fatalf("calls = %q, want GetPlexdHook, CreateJob", got)
			}
			got, err := json.Marshal(api.created[0])
			if err != nil {
				t.Fatal(err)
			}
			requireSameJSON(t, got, fmt.Sprintf(hookJobDocument, tc.activeDeadline, tc.command, tc.securityContext))

			created := logs.find(slog.LevelInfo, "plexd hook job created")
			if len(created) != 1 {
				t.Fatalf("got %d plexd hook job created lines, want 1", len(created))
			}
			wantAttrs := map[string]string{
				"component":        "plexdhook-jobs",
				"execution_id":     testExecutionID,
				"hook":             "nightly-backup",
				"job":              "plexdhook-078a49b48bea93928ef8732ddf0981db",
				"deadline_seconds": tc.deadlineSeconds,
			}
			if !reflect.DeepEqual(created[0].attrs, wantAttrs) {
				t.Errorf("log attrs = %v, want %v", created[0].attrs, wantAttrs)
			}
		})
	}
}

// envOf returns the hook container's environment of the one Job api created.
func envOf(t *testing.T, api *fakeHookJobAPI) []HookEnvVar {
	t.Helper()
	if len(api.created) != 1 {
		t.Fatalf("created %d Jobs, want 1", len(api.created))
	}
	return api.created[0].Spec.Template.Spec.Containers[0].Env
}

// A dispatch parameter overrides the resource's of the same name. Within each
// source a later write to the same variable wins: the resource's in list
// order, the dispatch's in ascending name order.
func TestHookJobRunner_StartEnvironment(t *testing.T) {
	hook := testPlexdHook()
	hook.Spec.Parameters = []PlexdHookParam{
		{Name: "target", Value: "/var/backups"},
		{Name: "retention", Value: "7d"},
		{Name: "my-mode", Value: "first"},
		{Name: "my_mode", Value: "second"},
	}
	api := &fakeHookJobAPI{hook: hook}
	r, _ := newTestHookJobRunner(t, api)

	run := testRun(time.Minute, map[string]string{
		"target":    "/srv",
		"disk-path": "/dev/sda",
		"b_c":       "underscore",
		"b-c":       "dash",
	})
	if err := r.Start(context.Background(), run); err != nil {
		t.Fatalf("Start: %v", err)
	}

	want := []HookEnvVar{
		{Name: "PLEXD_EXECUTION_ID", Value: testExecutionID},
		{Name: "PLEXD_HOOK_NAME", Value: "backup"},
		{Name: "PLEXD_NODE_ID", Value: testNodeID},
		// "b-c" sorts before "b_c", so the underscore is written last.
		{Name: "PLEXD_PARAM_B_C", Value: "underscore"},
		{Name: "PLEXD_PARAM_DISK_PATH", Value: "/dev/sda"},
		{Name: "PLEXD_PARAM_MY_MODE", Value: "second"},
		{Name: "PLEXD_PARAM_RETENTION", Value: "7d"},
		{Name: "PLEXD_PARAM_TARGET", Value: "/srv"},
	}
	if got := envOf(t, api); !reflect.DeepEqual(got, want) {
		t.Errorf("env = %+v\nwant  %+v", got, want)
	}
}

func TestHookJobRunner_StartWithoutParameters(t *testing.T) {
	hook := testPlexdHook()
	hook.Spec.Parameters = nil
	api := &fakeHookJobAPI{hook: hook}
	r, _ := newTestHookJobRunner(t, api)

	run := testRun(time.Minute, nil)
	run.Parameters = nil
	if err := r.Start(context.Background(), run); err != nil {
		t.Fatalf("Start: %v", err)
	}

	want := []HookEnvVar{
		{Name: "PLEXD_EXECUTION_ID", Value: testExecutionID},
		{Name: "PLEXD_HOOK_NAME", Value: "backup"},
		{Name: "PLEXD_NODE_ID", Value: testNodeID},
	}
	if got := envOf(t, api); !reflect.DeepEqual(got, want) {
		t.Errorf("env = %+v\nwant  %+v", got, want)
	}
}

// A hook the runner refuses gets no Job.
func TestHookJobRunner_StartRefusesHook(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*PlexdHook)
		params map[string]string
		want   string
	}{
		{
			name:   "tag image",
			modify: func(h *PlexdHook) { h.Spec.JobTemplate.Image = "registry.example/backup:1.4" },
			want:   "plexd hook image is not pinned by a sha256 digest: registry.example/backup:1.4",
		},
		{
			name:   "no jobTemplate",
			modify: func(h *PlexdHook) { h.Spec.JobTemplate = nil },
			want:   "plexd hook image is not pinned by a sha256 digest: busybox:latest",
		},
		{
			name:   "NUL in a dispatch value",
			params: map[string]string{"target": "/srv\x00/etc"},
			want:   "plexd hook parameter target contains a NUL character",
		},
		{
			name:   "NUL in a dispatch name",
			params: map[string]string{"tar\x00get": "/srv"},
			want:   `plexd hook parameter tar\x00get contains a NUL character`,
		},
		{
			name:   "NUL in a resource value",
			modify: func(h *PlexdHook) { h.Spec.Parameters = []PlexdHookParam{{Name: "retention", Value: "7\x00d"}} },
			want:   "plexd hook parameter retention contains a NUL character",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := testPlexdHook()
			if tc.modify != nil {
				tc.modify(hook)
			}
			api := &fakeHookJobAPI{hook: hook}
			r, _ := newTestHookJobRunner(t, api)

			err := r.Start(context.Background(), testRun(time.Minute, tc.params))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("Start = %v, want %q", err, tc.want)
			}
			if got := api.callsSnapshot(); !slices.Equal(got, []string{"GetPlexdHook"}) {
				t.Errorf("calls = %q, want GetPlexdHook alone", got)
			}
		})
	}
}

func TestHookJobRunner_StartGetPlexdHookErrors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		api := &fakeHookJobAPI{hookErr: fmt.Errorf("kubernetes: get plexdhook: status 404: %w", ErrNotFound)}
		r, _ := newTestHookJobRunner(t, api)

		err := r.Start(context.Background(), testRun(time.Minute, nil))
		if !errors.Is(err, actions.ErrPlexdHookNotFound) {
			t.Fatalf("Start = %v, want actions.ErrPlexdHookNotFound", err)
		}
		if api.count("CreateJob") != 0 {
			t.Error("CreateJob called for a hook that does not exist")
		}
	})

	t.Run("unauthorized", func(t *testing.T) {
		api := &fakeHookJobAPI{hookErr: fmt.Errorf("kubernetes: get plexdhook: status 403: %w", ErrUnauthorized)}
		r, _ := newTestHookJobRunner(t, api)

		err := r.Start(context.Background(), testRun(time.Minute, nil))
		if !errors.Is(err, ErrUnauthorized) || !strings.HasPrefix(err.Error(), "get plexd hook: ") {
			t.Fatalf("Start = %v, want get plexd hook: wrapping ErrUnauthorized", err)
		}
		if errors.Is(err, actions.ErrPlexdHookNotFound) {
			t.Errorf("Start = %v, want it not to read as a missing hook", err)
		}
		if api.count("CreateJob") != 0 {
			t.Error("CreateJob called after the hook could not be read")
		}
	})
}

func TestHookJobRunner_StartCreateJobErrors(t *testing.T) {
	t.Run("already exists", func(t *testing.T) {
		api := &fakeHookJobAPI{hook: testPlexdHook(), createErr: fmt.Errorf("kubernetes: create job: status 409: %w", ErrAlreadyExists)}
		r, _ := newTestHookJobRunner(t, api)

		if err := r.Start(context.Background(), testRun(time.Minute, nil)); err != nil {
			t.Fatalf("Start = %v, want nil for a Job that already exists", err)
		}
	})

	t.Run("unauthorized", func(t *testing.T) {
		api := &fakeHookJobAPI{hook: testPlexdHook(), createErr: fmt.Errorf("kubernetes: create job: status 403: %w", ErrUnauthorized)}
		r, logs := newTestHookJobRunner(t, api)

		err := r.Start(context.Background(), testRun(time.Minute, nil))
		if !errors.Is(err, ErrUnauthorized) || !strings.HasPrefix(err.Error(), "create job: ") {
			t.Fatalf("Start = %v, want create job: wrapping ErrUnauthorized", err)
		}
		if n := len(logs.find(slog.LevelInfo, "plexd hook job created")); n != 0 {
			t.Errorf("got %d plexd hook job created lines for a Job that was not created", n)
		}
	})
}

func TestHookJobRunner_WaitCompletes(t *testing.T) {
	api := &fakeHookJobAPI{
		getJob: func(_ context.Context, n int) (JobState, error) {
			return JobState{Complete: n == 3}, nil
		},
		pods: []JobPod{
			{Name: "pod-old", CreatedAt: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC), ExitCode: intPtr(1)},
			{Name: "pod-new", CreatedAt: time.Date(2026, 11, 14, 10, 5, 0, 0, time.UTC), ExitCode: intPtr(0)},
		},
		logs: map[string]string{"pod-old": "old\n", "pod-new": "done\n"},
	}
	r, _ := newTestHookJobRunner(t, api)

	res, err := r.Wait(waitCtx(t), testExecutionID, time.Hour)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	want := actions.PlexdHookResult{Succeeded: true, ExitCode: intPtr(0), Output: "done\n"}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("Wait = %+v, want %+v", res, want)
	}
	if api.getJobCalls != 3 {
		t.Errorf("GetJob called %d times, want 3", api.getJobCalls)
	}
	jobName := hookJobName(testNodeID, testExecutionID)
	for _, name := range api.getJobNames {
		if name != jobName {
			t.Errorf("GetJob of %q, want %q", name, jobName)
		}
	}
	if !slices.Equal(api.logPods, []string{"pod-new"}) {
		t.Errorf("logs read from %q, want the newest pod", api.logPods)
	}
	if !slices.Equal(api.logLimits, []int64{testOutputLimit + 1}) {
		t.Errorf("limitBytes = %v, want %d", api.logLimits, testOutputLimit+1)
	}
	if api.count("DeleteJob") != 0 {
		t.Error("DeleteJob called for a Job that completed")
	}
}

// The backstop deleted the pods with their log, so there is nothing to read.
func TestHookJobRunner_WaitDeadlineExceeded(t *testing.T) {
	api := &fakeHookJobAPI{
		getJob: func(context.Context, int) (JobState, error) {
			return JobState{Failed: true, Reason: "DeadlineExceeded", Message: "Job was active longer than specified deadline"}, nil
		},
	}
	r, _ := newTestHookJobRunner(t, api)

	res, err := r.Wait(waitCtx(t), testExecutionID, time.Hour)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if !reflect.DeepEqual(res, actions.PlexdHookResult{TimedOut: true}) {
		t.Errorf("Wait = %+v, want TimedOut alone", res)
	}
	if got := api.callsSnapshot(); !slices.Equal(got, []string{"GetJob"}) {
		t.Errorf("calls = %q, want GetJob alone", got)
	}
}

func TestHookJobRunner_WaitFailed(t *testing.T) {
	failed := JobState{Failed: true, Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit"}

	t.Run("no pod left", func(t *testing.T) {
		api := &fakeHookJobAPI{getJob: func(context.Context, int) (JobState, error) { return failed, nil }}
		r, _ := newTestHookJobRunner(t, api)

		res, err := r.Wait(waitCtx(t), testExecutionID, time.Hour)
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
		want := actions.PlexdHookResult{Reason: "plexd hook job failed: BackoffLimitExceeded: Job has reached the specified backoff limit"}
		if !reflect.DeepEqual(res, want) {
			t.Errorf("Wait = %+v, want %+v", res, want)
		}
		if api.count("PodLog") != 0 {
			t.Error("PodLog called without a pod")
		}
	})

	t.Run("container exited", func(t *testing.T) {
		api := &fakeHookJobAPI{
			getJob: func(context.Context, int) (JobState, error) { return failed, nil },
			pods:   []JobPod{{Name: "pod-1", ExitCode: intPtr(3)}},
			logs:   map[string]string{"pod-1": "boom\n"},
		}
		r, _ := newTestHookJobRunner(t, api)

		res, err := r.Wait(waitCtx(t), testExecutionID, time.Hour)
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
		want := actions.PlexdHookResult{ExitCode: intPtr(3), Output: "boom\n"}
		if !reflect.DeepEqual(res, want) {
			t.Errorf("Wait = %+v, want %+v", res, want)
		}
	})
}

// Past its bound, Wait reads the log first, because a deleted Job takes its
// pod's log with it, and then deletes the Job.
func TestHookJobRunner_WaitPastBound(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pods       []JobPod
		wantReason string
		wantOutput string
		wantCalls  []string // the calls after the last GetJob
	}{
		{
			name:       "running",
			pods:       []JobPod{{Name: "pod-1"}},
			wantOutput: "partial\n",
			wantCalls:  []string{"ListJobPods", "PodLog", "DeleteJob"},
		},
		{
			name:       "image pull failing",
			pods:       []JobPod{{Name: "pod-1", WaitingReason: "ErrImagePull"}},
			wantReason: "hook container never started: ErrImagePull",
			wantOutput: "partial\n",
			wantCalls:  []string{"ListJobPods", "PodLog", "DeleteJob"},
		},
		{
			name:       "no pod",
			wantReason: "hook container never started",
			wantCalls:  []string{"ListJobPods", "DeleteJob"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeHookJobAPI{
				pods: tc.pods,
				logs: map[string]string{"pod-1": "partial\n"},
			}
			r, _ := newTestHookJobRunner(t, api)

			res, err := r.Wait(waitCtx(t), testExecutionID, 5*time.Millisecond)
			if err != nil {
				t.Fatalf("Wait: %v", err)
			}
			want := actions.PlexdHookResult{TimedOut: true, Reason: tc.wantReason, Output: tc.wantOutput}
			if !reflect.DeepEqual(res, want) {
				t.Errorf("Wait = %+v, want %+v", res, want)
			}
			calls := api.callsSnapshot()
			last := slices.Index(calls, "ListJobPods")
			if last < 1 || calls[last-1] != "GetJob" || !slices.Equal(calls[last:], tc.wantCalls) {
				t.Errorf("calls = %q, want GetJob calls and then %q", calls, tc.wantCalls)
			}
			if !slices.Equal(api.deleted, []string{hookJobName(testNodeID, testExecutionID)}) {
				t.Errorf("deleted %q, want the run's Job once", api.deleted)
			}
		})
	}

	t.Run("delete fails", func(t *testing.T) {
		api := &fakeHookJobAPI{deleteErr: fmt.Errorf("kubernetes: delete job: status 403: %w", ErrUnauthorized)}
		r, logs := newTestHookJobRunner(t, api)

		res, err := r.Wait(waitCtx(t), testExecutionID, 5*time.Millisecond)
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
		if !res.TimedOut {
			t.Errorf("Wait = %+v, want TimedOut", res)
		}
		if got := logs.warnings(); !slices.Equal(got, []string{"plexd hook job delete failed"}) {
			t.Errorf("warnings = %q, want one plexd hook job delete failed", got)
		}
	})
}

// A bound already used up, as a resumed run past its deadline has, collects
// and deletes the Job after the status read and the one more read at the bound
// both find it running.
func TestHookJobRunner_WaitZeroBound(t *testing.T) {
	api := &fakeHookJobAPI{pods: []JobPod{{Name: "pod-1"}}, logs: map[string]string{"pod-1": "partial\n"}}
	r, _ := newTestHookJobRunner(t, api)
	r.pollInterval = time.Hour

	res, err := r.Wait(waitCtx(t), testExecutionID, 0)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if want := (actions.PlexdHookResult{TimedOut: true, Output: "partial\n"}); !reflect.DeepEqual(res, want) {
		t.Errorf("Wait = %+v, want %+v", res, want)
	}
	if got := api.callsSnapshot(); !slices.Equal(got, []string{"GetJob", "GetJob", "ListJobPods", "PodLog", "DeleteJob"}) {
		t.Errorf("calls = %q", got)
	}
}

// A Job that ended after the last status read but before the bound is reported
// as it ended, not as timed out, and is not deleted: the status is read once
// more at the bound, and a hook container found terminated after that read
// finished too.
func TestHookJobRunner_WaitBoundAfterTheJobEnded(t *testing.T) {
	for _, tc := range []struct {
		name string
		// complete has the read at the bound find the Job Complete; without
		// it the Job reads as running and only its pod has ended.
		complete bool
		exitCode int
		want     actions.PlexdHookResult
	}{
		{
			name:     "status read at the bound finds it complete",
			complete: true,
			want:     actions.PlexdHookResult{Succeeded: true, ExitCode: intPtr(0), Output: "done\n"},
		},
		{
			name: "container exited 0 after the last read",
			want: actions.PlexdHookResult{Succeeded: true, ExitCode: intPtr(0), Output: "done\n"},
		},
		{
			name:     "container exited 3 after the last read",
			exitCode: 3,
			want:     actions.PlexdHookResult{ExitCode: intPtr(3), Output: "done\n"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeHookJobAPI{
				getJob: func(_ context.Context, n int) (JobState, error) {
					return JobState{Complete: tc.complete && n == 2}, nil
				},
				pods: []JobPod{{Name: "pod-1", ExitCode: intPtr(tc.exitCode)}},
				logs: map[string]string{"pod-1": "done\n"},
			}
			r, logs := newTestHookJobRunner(t, api)
			r.pollInterval = time.Hour

			res, err := r.Wait(waitCtx(t), testExecutionID, 0)
			if err != nil {
				t.Fatalf("Wait: %v", err)
			}
			if !reflect.DeepEqual(res, tc.want) {
				t.Errorf("Wait = %+v, want %+v", res, tc.want)
			}
			if got := api.callsSnapshot(); !slices.Equal(got, []string{"GetJob", "GetJob", "ListJobPods", "PodLog"}) {
				t.Errorf("calls = %q, want two status reads and the outcome read, no delete", got)
			}
			if got := logs.warnings(); len(got) != 0 {
				t.Errorf("warnings = %q, want none", got)
			}
		})
	}
}

// A context that ends while Wait reads the outcome of a Job it found over, or
// times out one whose bound passed, ends Wait with the context's error and no
// delete, rather than with an outcome missing its exit code and log: the
// executor then stops the Job on a cancel, or leaves it for the next agent on
// a shutdown.
func TestHookJobRunner_WaitContextEndsWhileReadingTheOutcome(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state JobState
		bound time.Duration
	}{
		{name: "complete", state: JobState{Complete: true}, bound: time.Hour},
		{name: "failed", state: JobState{Failed: true, Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit"}, bound: time.Hour},
		{name: "past the bound", bound: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(waitCtx(t))
			defer cancel()
			api := &fakeHookJobAPI{
				getJob:     func(context.Context, int) (JobState, error) { return tc.state, nil },
				beforeList: cancel,
				pods:       []JobPod{{Name: "pod-1", ExitCode: intPtr(3)}},
				logs:       map[string]string{"pod-1": "boom\n"},
			}
			r, _ := newTestHookJobRunner(t, api)
			r.pollInterval = time.Hour

			res, err := r.Wait(ctx, testExecutionID, tc.bound)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Wait = %+v, %v; want context.Canceled", res, err)
			}
			if api.count("DeleteJob") != 0 {
				t.Errorf("DeleteJob called %d times, want none", api.count("DeleteJob"))
			}
		})
	}

	// The outcome read at the bound succeeds and the context ends right
	// before the delete: the Job still runs, so the caller decides what
	// becomes of it.
	t.Run("during the delete past the bound", func(t *testing.T) {
		ctx, cancel := context.WithCancel(waitCtx(t))
		defer cancel()
		api := &fakeHookJobAPI{pods: []JobPod{{Name: "pod-1"}}, logs: map[string]string{"pod-1": "partial\n"}}
		r, logs := newTestHookJobRunner(t, api)
		r.pollInterval = time.Hour
		r.client = &cancelBeforeDelete{fakeHookJobAPI: api, cancel: cancel}

		res, err := r.Wait(ctx, testExecutionID, 0)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait = %+v, %v; want context.Canceled", res, err)
		}
		if got := logs.warnings(); len(got) != 0 {
			t.Errorf("warnings = %q, want none: a delete the context cut short is the caller's", got)
		}
	})
}

// cancelBeforeDelete ends a context right before the DeleteJob it passes on.
type cancelBeforeDelete struct {
	*fakeHookJobAPI
	cancel context.CancelFunc
}

func (c *cancelBeforeDelete) DeleteJob(ctx context.Context, namespace, name string) error {
	c.cancel()
	return c.fakeHookJobAPI.DeleteJob(ctx, namespace, name)
}

// A failed status read is logged once per streak of failures and read again.
func TestHookJobRunner_WaitRetriesStatusReads(t *testing.T) {
	refused := errors.New("kubernetes: get job: dial tcp 10.96.0.1:443: connect: connection refused")

	t.Run("one streak", func(t *testing.T) {
		api := &fakeHookJobAPI{
			getJob: func(_ context.Context, n int) (JobState, error) {
				if n <= 2 {
					return JobState{}, refused
				}
				return JobState{Complete: true}, nil
			},
			pods: []JobPod{{Name: "pod-1", ExitCode: intPtr(0)}},
			logs: map[string]string{"pod-1": "ok\n"},
		}
		r, logs := newTestHookJobRunner(t, api)

		res, err := r.Wait(waitCtx(t), testExecutionID, time.Hour)
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
		if want := (actions.PlexdHookResult{Succeeded: true, ExitCode: intPtr(0), Output: "ok\n"}); !reflect.DeepEqual(res, want) {
			t.Errorf("Wait = %+v, want %+v", res, want)
		}
		warned := logs.find(slog.LevelWarn, "plexd hook job status read failed")
		if len(warned) != 1 {
			t.Fatalf("got %d status read warnings, want 1", len(warned))
		}
		if warned[0].attrs["execution_id"] != testExecutionID || warned[0].attrs["job"] != hookJobName(testNodeID, testExecutionID) || warned[0].attrs["error"] != refused.Error() {
			t.Errorf("warning attrs = %v", warned[0].attrs)
		}
	})

	t.Run("two streaks", func(t *testing.T) {
		api := &fakeHookJobAPI{
			getJob: func(_ context.Context, n int) (JobState, error) {
				switch n {
				case 1, 3, 4:
					return JobState{}, refused
				case 2:
					return JobState{}, nil
				}
				return JobState{Complete: true}, nil
			},
		}
		r, logs := newTestHookJobRunner(t, api)

		if _, err := r.Wait(waitCtx(t), testExecutionID, time.Hour); err != nil {
			t.Fatalf("Wait: %v", err)
		}
		if n := len(logs.find(slog.LevelWarn, "plexd hook job status read failed")); n != 2 {
			t.Errorf("got %d status read warnings, want 2", n)
		}
	})
}

func TestHookJobRunner_WaitJobNotFound(t *testing.T) {
	api := &fakeHookJobAPI{
		getJob: func(context.Context, int) (JobState, error) {
			return JobState{}, fmt.Errorf("kubernetes: get job: status 404: %w", ErrNotFound)
		},
	}
	r, _ := newTestHookJobRunner(t, api)

	res, err := r.Wait(waitCtx(t), testExecutionID, time.Hour)
	if !errors.Is(err, actions.ErrPlexdHookJobNotFound) {
		t.Fatalf("Wait = %+v, %v; want actions.ErrPlexdHookJobNotFound", res, err)
	}
	if api.count("DeleteJob") != 0 {
		t.Error("DeleteJob called for a Job that is gone")
	}
}

// An outcome without its output is still the outcome.
func TestHookJobRunner_WaitOutputUnavailable(t *testing.T) {
	unauthorized := fmt.Errorf("kubernetes: read log: status 403: %w", ErrUnauthorized)

	t.Run("log read fails", func(t *testing.T) {
		api := &fakeHookJobAPI{
			getJob: func(context.Context, int) (JobState, error) {
				return JobState{Failed: true, Reason: "BackoffLimitExceeded"}, nil
			},
			pods:   []JobPod{{Name: "pod-1", ExitCode: intPtr(3)}},
			logErr: unauthorized,
		}
		r, logs := newTestHookJobRunner(t, api)

		res, err := r.Wait(waitCtx(t), testExecutionID, time.Hour)
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
		if want := (actions.PlexdHookResult{ExitCode: intPtr(3)}); !reflect.DeepEqual(res, want) {
			t.Errorf("Wait = %+v, want %+v", res, want)
		}
		if got := logs.warnings(); !slices.Equal(got, []string{"plexd hook output unavailable"}) {
			t.Errorf("warnings = %q, want one plexd hook output unavailable", got)
		}
	})

	t.Run("pod list fails", func(t *testing.T) {
		api := &fakeHookJobAPI{
			getJob:  func(context.Context, int) (JobState, error) { return JobState{Complete: true}, nil },
			listErr: unauthorized,
		}
		r, logs := newTestHookJobRunner(t, api)

		res, err := r.Wait(waitCtx(t), testExecutionID, time.Hour)
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
		if want := (actions.PlexdHookResult{Succeeded: true}); !reflect.DeepEqual(res, want) {
			t.Errorf("Wait = %+v, want %+v", res, want)
		}
		if api.count("PodLog") != 0 {
			t.Error("PodLog called without a pod list")
		}
		if got := logs.warnings(); !slices.Equal(got, []string{"plexd hook output unavailable"}) {
			t.Errorf("warnings = %q, want one plexd hook output unavailable", got)
		}
	})

	t.Run("pod list fails past the bound", func(t *testing.T) {
		api := &fakeHookJobAPI{listErr: unauthorized}
		r, _ := newTestHookJobRunner(t, api)

		res, err := r.Wait(waitCtx(t), testExecutionID, 5*time.Millisecond)
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
		// Without the pods nothing says whether the container started.
		if want := (actions.PlexdHookResult{TimedOut: true}); !reflect.DeepEqual(res, want) {
			t.Errorf("Wait = %+v, want %+v", res, want)
		}
		if api.count("DeleteJob") != 1 {
			t.Errorf("DeleteJob called %d times, want 1", api.count("DeleteJob"))
		}
	})
}

// A Wait whose context ends leaves the Job to whoever ended it.
func TestHookJobRunner_WaitContextCancelled(t *testing.T) {
	for _, tc := range []struct {
		name string
		// fail has the status read that sees the cancel fail with the
		// context's error, as a real one does.
		fail bool
	}{
		{name: "between polls"},
		{name: "during a status read", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(waitCtx(t))
			defer cancel()
			api := &fakeHookJobAPI{
				getJob: func(callCtx context.Context, _ int) (JobState, error) {
					cancel()
					if tc.fail {
						return JobState{}, fmt.Errorf("kubernetes: get job: %w", callCtx.Err())
					}
					return JobState{}, nil
				},
			}
			r, logs := newTestHookJobRunner(t, api)
			r.pollInterval = time.Hour

			_, err := r.Wait(ctx, testExecutionID, time.Hour)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Wait = %v, want context.Canceled", err)
			}
			if got := api.callsSnapshot(); !slices.Equal(got, []string{"GetJob"}) {
				t.Errorf("calls = %q, want GetJob alone", got)
			}
			if got := logs.warnings(); len(got) != 0 {
				t.Errorf("warnings = %q, want none", got)
			}
		})
	}
}

func TestHookJobRunner_Stop(t *testing.T) {
	jobName := hookJobName(testNodeID, testExecutionID)

	t.Run("no pod", func(t *testing.T) {
		api := &fakeHookJobAPI{}
		r, _ := newTestHookJobRunner(t, api)

		output, err := r.Stop(context.Background(), testExecutionID)
		if err != nil || output != "" {
			t.Fatalf("Stop = %q, %v; want an empty output and nil", output, err)
		}
		if got := api.callsSnapshot(); !slices.Equal(got, []string{"ListJobPods", "DeleteJob"}) {
			t.Errorf("calls = %q, want ListJobPods, DeleteJob", got)
		}
		if !slices.Equal(api.deleted, []string{jobName}) {
			t.Errorf("deleted %q, want %q", api.deleted, jobName)
		}
	})

	t.Run("running pod", func(t *testing.T) {
		api := &fakeHookJobAPI{
			pods: []JobPod{{Name: "pod-1"}},
			logs: map[string]string{"pod-1": "slow-started\n"},
		}
		r, _ := newTestHookJobRunner(t, api)

		output, err := r.Stop(context.Background(), testExecutionID)
		if err != nil || output != "slow-started\n" {
			t.Fatalf("Stop = %q, %v; want the log and nil", output, err)
		}
		if got := api.callsSnapshot(); !slices.Equal(got, []string{"ListJobPods", "PodLog", "DeleteJob"}) {
			t.Errorf("calls = %q, want the log read before the delete", got)
		}
	})

	// A log read that does not answer gets half of Stop's time, so the delete
	// still runs on a context that has not ended.
	t.Run("log read stalls", func(t *testing.T) {
		api := &fakeHookJobAPI{pods: []JobPod{{Name: "pod-1"}}, logBlocks: true}
		r, logs := newTestHookJobRunner(t, api)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		output, err := r.Stop(ctx, testExecutionID)
		if err != nil || output != "" {
			t.Fatalf("Stop = %q, %v; want an empty output and nil", output, err)
		}
		if !slices.Equal(api.deleted, []string{jobName}) {
			t.Errorf("deleted %q, want %q", api.deleted, jobName)
		}
		if got := logs.warnings(); !slices.Equal(got, []string{"plexd hook output unavailable"}) {
			t.Errorf("warnings = %q, want one plexd hook output unavailable", got)
		}
	})

	t.Run("delete fails", func(t *testing.T) {
		api := &fakeHookJobAPI{deleteErr: fmt.Errorf("kubernetes: delete job: status 403: %w", ErrUnauthorized)}
		r, _ := newTestHookJobRunner(t, api)

		_, err := r.Stop(context.Background(), testExecutionID)
		if !errors.Is(err, ErrUnauthorized) || !strings.HasPrefix(err.Error(), "delete job: ") {
			t.Fatalf("Stop = %v, want delete job: wrapping ErrUnauthorized", err)
		}
		if api.count("DeleteJob") != 1 {
			t.Errorf("DeleteJob called %d times, want 1", api.count("DeleteJob"))
		}
	})
}

// Every call gets a context of its own, bounded by the request timeout, so an
// API server that does not answer cannot hold a run.
func TestHookJobRunner_EachCallHasRequestTimeout(t *testing.T) {
	api := &fakeHookJobAPI{
		hook:   testPlexdHook(),
		getJob: func(context.Context, int) (JobState, error) { return JobState{Complete: true}, nil },
		pods:   []JobPod{{Name: "pod-1", ExitCode: intPtr(0)}},
	}
	r, _ := newTestHookJobRunner(t, api)
	r.requestTimeout = 7 * time.Second

	// The outer context has a far deadline, so only the request timeout can
	// bring a call's deadline under it.
	ctx := waitCtx(t)
	if err := r.Start(ctx, testRun(time.Minute, nil)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := r.Wait(ctx, testExecutionID, time.Hour); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if _, err := r.Stop(ctx, testExecutionID); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	calls := api.callsSnapshot()
	for _, method := range []string{"GetPlexdHook", "CreateJob", "GetJob", "ListJobPods", "PodLog", "DeleteJob"} {
		if !slices.Contains(calls, method) {
			t.Errorf("calls = %q, want %s among them", calls, method)
		}
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	for i, left := range api.deadlines {
		if left <= 0 || left > 7*time.Second {
			t.Errorf("call %d (%s) had %v left, want at most the 7s request timeout", i, calls[i], left)
		}
	}
}

func TestNewHookJobRunner_Defaults(t *testing.T) {
	r := NewHookJobRunner(&fakeHookJobAPI{}, HookJobConfig{}, testLogger())
	// The values are written out rather than taken from the constants, so a
	// change to one shows up here.
	if r.pollInterval != 2*time.Second || r.backstop != 30*time.Second || r.requestTimeout != 10*time.Second || r.ttlSeconds != 3600 {
		t.Errorf("poll %v, backstop %v, request timeout %v, ttl %d; want 2s, 30s, 10s, 3600",
			r.pollInterval, r.backstop, r.requestTimeout, r.ttlSeconds)
	}
}
