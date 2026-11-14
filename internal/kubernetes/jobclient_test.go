package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// newFakeJobAPIServer starts a fake API server the way newFakeAPIServer does
// and returns a JobClient on the connection newAPIServer built for it, which is
// the connection newJobClient builds. The token path comes back so a test can
// rewrite or remove the file.
func newFakeJobAPIServer(t *testing.T, handler http.HandlerFunc) (*JobClient, string) {
	t.Helper()
	lister, tokenPath := newFakeAPIServer(t, handler)
	return &JobClient{apiServer: lister.apiServer}, tokenPath
}

// observeJobBody is observeBody for a JobClient. The client's *http.Client is
// shared with the lister it came from, so wrapping its transport there wraps
// it for the JobClient.
func observeJobBody(c *JobClient, readBytes int) *observedBody {
	return observeBody(&HookLister{apiServer: c.apiServer}, readBytes)
}

// jobAPIRequest is what the fake API server saw of one request.
type jobAPIRequest struct {
	method, path, query, body, contentType, accept, authorization string
}

// recordJobAPIRequest reads r into a jobAPIRequest. The path is the escaped
// one, so a test sees what url.PathEscape made of a name.
func recordJobAPIRequest(r *http.Request) jobAPIRequest {
	body, _ := io.ReadAll(r.Body)
	return jobAPIRequest{
		method:        r.Method,
		path:          r.URL.EscapedPath(),
		query:         r.URL.RawQuery,
		body:          string(body),
		contentType:   r.Header.Get("Content-Type"),
		accept:        r.Header.Get("Accept"),
		authorization: r.Header.Get("Authorization"),
	}
}

const (
	testJobName = "plexdhook-078a49b48bea93928ef8732ddf0981db"

	plexdHookItemPath = "/apis/plexd.plexsphere.com/v1alpha1/namespaces/plexd-system/plexdhooks/nightly-backup"
	jobsCollPath      = "/apis/batch/v1/namespaces/plexd-system/jobs"
	jobItemPath       = jobsCollPath + "/" + testJobName
	podsCollPath      = "/api/v1/namespaces/plexd-system/pods"
	podLogPath        = podsCollPath + "/" + testJobName + "-x7k2p/log"

	// plexdHookItemBody is one PlexdHook as a GET of it answers.
	plexdHookItemBody = `{
	  "apiVersion": "plexd.plexsphere.com/v1alpha1",
	  "kind": "PlexdHook",
	  "metadata": {
	    "name": "nightly-backup",
	    "namespace": "plexd-system",
	    "uid": "5b9e2a7c-3f1d-4c2e-9a8b-0c1d2e3f4a5b",
	    "resourceVersion": "4710"
	  },
	  "spec": {
	    "hookName": "backup",
	    "jobTemplate": {
	      "image": "registry.example/backup@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	      "command": ["/bin/backup"]
	    },
	    "parameters": [{"name": "retention", "value": "7d"}]
	  }
	}`

	// jobPodListBody holds the pods of a Job: one whose hook container
	// exited 3 beside a sidecar that exited 9, one whose hook container waits
	// on its image, and one with no container status yet.
	jobPodListBody = `{
	  "kind": "PodList",
	  "apiVersion": "v1",
	  "items": [
	    {
	      "metadata": {"name": "plexdhook-a-1", "creationTimestamp": "2026-11-14T10:00:00Z"},
	      "status": {"containerStatuses": [
	        {"name": "sidecar", "state": {"terminated": {"exitCode": 9, "reason": "Error"}}},
	        {"name": "hook", "state": {"terminated": {"exitCode": 3, "reason": "Error"}}}
	      ]}
	    },
	    {
	      "metadata": {"name": "plexdhook-a-2", "creationTimestamp": "2026-11-14T10:01:00Z"},
	      "status": {"containerStatuses": [
	        {"name": "hook", "state": {"waiting": {"reason": "ErrImagePull", "message": "failed to pull image"}}}
	      ]}
	    },
	    {
	      "metadata": {"name": "plexdhook-a-3", "creationTimestamp": "2026-11-14T10:02:00Z"},
	      "status": {"phase": "Pending"}
	    }
	  ]
	}`
)

// testHookJob is a small Job for the requests that send one.
func testHookJob() *HookJob {
	return &HookJob{
		APIVersion: "batch/v1",
		Kind:       "Job",
		Metadata:   HookJobMetadata{Name: testJobName},
	}
}

// Every method sends the request of its row in the issue's table, and the
// token is read for each call: the file changes before every one of them.
func TestJobClient_Requests(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []jobAPIRequest
	)
	client, tokenPath := newFakeJobAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		req := recordJobAPIRequest(r)
		mu.Lock()
		seen = append(seen, req)
		mu.Unlock()

		switch req.method + " " + req.path {
		case "GET " + plexdHookItemPath:
			_, _ = io.WriteString(w, plexdHookItemBody)
		case "POST " + jobsCollPath:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, req.body)
		case "GET " + jobItemPath:
			_, _ = io.WriteString(w, `{"kind":"Job","status":{"conditions":[{"type":"Complete","status":"True","reason":"CompletionsReached","message":"Reached expected number of succeeded pods"}]}}`)
		case "DELETE " + jobItemPath:
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Success"}`)
		case "GET " + podsCollPath:
			_, _ = io.WriteString(w, jobPodListBody)
		case "GET " + podLogPath:
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "line one\nline two\n")
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	})

	ctx := context.Background()
	call := 0
	nextToken := func() {
		t.Helper()
		call++
		if err := os.WriteFile(tokenPath, []byte(fmt.Sprintf("sa-token-%d\n", call)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	nextToken()
	hook, err := client.GetPlexdHook(ctx, "plexd-system", "nightly-backup")
	if err != nil {
		t.Fatalf("GetPlexdHook: %v", err)
	}
	wantHook := &PlexdHook{
		Name:            "nightly-backup",
		Namespace:       "plexd-system",
		UID:             "5b9e2a7c-3f1d-4c2e-9a8b-0c1d2e3f4a5b",
		ResourceVersion: "4710",
		Spec: PlexdHookSpec{
			HookName: "backup",
			JobTemplate: &PlexdHookJobTemplate{
				Image:   "registry.example/backup@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Command: []string{"/bin/backup"},
			},
			Parameters: []PlexdHookParam{{Name: "retention", Value: "7d"}},
		},
	}
	if !reflect.DeepEqual(hook, wantHook) {
		t.Errorf("GetPlexdHook = %+v\nwant           %+v", hook, wantHook)
	}

	nextToken()
	job := testHookJob()
	if err := client.CreateJob(ctx, "plexd-system", job); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	jobJSON, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}

	nextToken()
	state, err := client.GetJob(ctx, "plexd-system", testJobName)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	wantState := JobState{Complete: true, Reason: "CompletionsReached", Message: "Reached expected number of succeeded pods"}
	if state != wantState {
		t.Errorf("GetJob = %+v, want %+v", state, wantState)
	}

	nextToken()
	if err := client.DeleteJob(ctx, "plexd-system", testJobName); err != nil {
		t.Fatalf("DeleteJob: %v", err)
	}

	nextToken()
	pods, err := client.ListJobPods(ctx, "plexd-system", testJobName)
	if err != nil {
		t.Fatalf("ListJobPods: %v", err)
	}
	exit3 := 3
	wantPods := []JobPod{
		{Name: "plexdhook-a-1", CreatedAt: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC), ExitCode: &exit3},
		{Name: "plexdhook-a-2", CreatedAt: time.Date(2026, 11, 14, 10, 1, 0, 0, time.UTC), WaitingReason: "ErrImagePull"},
		{Name: "plexdhook-a-3", CreatedAt: time.Date(2026, 11, 14, 10, 2, 0, 0, time.UTC)},
	}
	if !reflect.DeepEqual(pods, wantPods) {
		t.Errorf("ListJobPods = %+v\nwant          %+v", pods, wantPods)
	}

	nextToken()
	text, err := client.PodLog(ctx, "plexd-system", testJobName+"-x7k2p", 1025)
	if err != nil {
		t.Fatalf("PodLog: %v", err)
	}
	if text != "line one\nline two\n" {
		t.Errorf("PodLog = %q, want the two lines", text)
	}

	const accept = "application/json, */*"
	want := []jobAPIRequest{
		{method: http.MethodGet, path: plexdHookItemPath, accept: accept, authorization: "Bearer sa-token-1"},
		{method: http.MethodPost, path: jobsCollPath, body: string(jobJSON), contentType: "application/json", accept: accept, authorization: "Bearer sa-token-2"},
		{method: http.MethodGet, path: jobItemPath, accept: accept, authorization: "Bearer sa-token-3"},
		{method: http.MethodDelete, path: jobItemPath, body: `{"propagationPolicy":"Background"}`, contentType: "application/json", accept: accept, authorization: "Bearer sa-token-4"},
		{method: http.MethodGet, path: podsCollPath, query: "labelSelector=job-name%3D" + testJobName, accept: accept, authorization: "Bearer sa-token-5"},
		{method: http.MethodGet, path: podLogPath, query: "container=hook&limitBytes=1025", accept: accept, authorization: "Bearer sa-token-6"},
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(want) {
		t.Fatalf("the API server saw %d requests, want %d: %+v", len(seen), len(want), seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("request %d = %+v\nwant        %+v", i+1, seen[i], want[i])
		}
	}
}

// A name that is not a plain path segment stays one segment.
func TestJobClient_EscapesNames(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	client, _ := newFakeJobAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.EscapedPath())
		mu.Unlock()
		_, _ = io.WriteString(w, `{}`)
	})

	ctx := context.Background()
	if _, err := client.GetJob(ctx, "plexd system", "a/b"); err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if _, err := client.GetPlexdHook(ctx, "plexd system", "a/b"); err != nil {
		t.Fatalf("GetPlexdHook: %v", err)
	}
	if _, err := client.PodLog(ctx, "plexd system", "a/b", 10); err != nil {
		t.Fatalf("PodLog: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"/apis/batch/v1/namespaces/plexd%20system/jobs/a%2Fb",
		"/apis/plexd.plexsphere.com/v1alpha1/namespaces/plexd%20system/plexdhooks/a%2Fb",
		"/api/v1/namespaces/plexd%20system/pods/a%2Fb/log",
	}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("paths = %q\nwant    %q", seen, want)
	}
}

func TestJobClient_ListJobPodsEmpty(t *testing.T) {
	client, _ := newFakeJobAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"kind":"PodList","apiVersion":"v1","items":[]}`)
	})

	pods, err := client.ListJobPods(context.Background(), "plexd-system", testJobName)
	if err != nil {
		t.Fatalf("ListJobPods: %v", err)
	}
	if pods == nil || len(pods) != 0 {
		t.Errorf("pods = %#v, want an empty, non-nil slice", pods)
	}
}

// jobClientCalls runs each JobClient method once against the same names.
var jobClientCalls = []struct {
	name string
	call func(*JobClient) error
}{
	{"GetPlexdHook", func(c *JobClient) error {
		_, err := c.GetPlexdHook(context.Background(), "plexd-system", "nightly-backup")
		return err
	}},
	{"CreateJob", func(c *JobClient) error {
		return c.CreateJob(context.Background(), "plexd-system", testHookJob())
	}},
	{"GetJob", func(c *JobClient) error {
		_, err := c.GetJob(context.Background(), "plexd-system", testJobName)
		return err
	}},
	{"DeleteJob", func(c *JobClient) error {
		return c.DeleteJob(context.Background(), "plexd-system", testJobName)
	}},
	{"ListJobPods", func(c *JobClient) error {
		_, err := c.ListJobPods(context.Background(), "plexd-system", testJobName)
		return err
	}},
	{"PodLog", func(c *JobClient) error {
		_, err := c.PodLog(context.Background(), "plexd-system", testJobName+"-x7k2p", 1025)
		return err
	}},
}

// Callers tell a missing grant, a missing object and an object that already
// exists apart by the sentinel. A 404 from DeleteJob is what it was after, so
// it is no error. Every other status quotes the Status message. The body is
// closed whatever the outcome.
func TestJobClient_StatusMapping(t *testing.T) {
	const invalid = `Job.batch "plexdhook-x" is invalid: spec.template.spec.containers[0].image: Required value`
	for _, tc := range []struct {
		status int
		body   string
		want   error  // the sentinel the error wraps
		text   string // what the error says after the call's name, when want is nil
	}{
		{status: http.StatusUnauthorized, want: ErrUnauthorized},
		{status: http.StatusForbidden, want: ErrUnauthorized},
		{status: http.StatusNotFound, want: ErrNotFound},
		{status: http.StatusConflict, want: ErrAlreadyExists},
		{
			status: http.StatusUnprocessableEntity,
			body:   `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":` + strconv.Quote(invalid) + `,"reason":"Invalid","code":422}`,
			text:   "unexpected status 422: " + invalid,
		},
		{status: http.StatusInternalServerError, body: `{"message":"not a Status"}`, text: "unexpected status 500"},
		{status: http.StatusBadGateway, body: "<html>bad gateway</html>", text: "unexpected status 502"},
	} {
		for _, c := range jobClientCalls {
			t.Run(fmt.Sprintf("%d/%s", tc.status, c.name), func(t *testing.T) {
				client, _ := newFakeJobAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
				})
				body := observeJobBody(client, 0)

				err := c.call(client)

				select {
				case <-body.closed:
				default:
					t.Error("response body left open")
				}
				if tc.status == http.StatusNotFound && c.name == "DeleteJob" {
					if err != nil {
						t.Errorf("DeleteJob = %v, want nil for a Job that is gone", err)
					}
					return
				}
				if err == nil {
					t.Fatalf("%s succeeded, want an error", c.name)
				}
				if tc.want != nil {
					if !errors.Is(err, tc.want) {
						t.Errorf("error = %v, want it to wrap %v", err, tc.want)
					}
					if want := fmt.Sprintf(": status %d: %v", tc.status, tc.want); !strings.Contains(err.Error(), want) {
						t.Errorf("error = %v, want it to contain %q", err, want)
					}
					return
				}
				for _, sentinel := range []error{ErrUnauthorized, ErrNotFound, ErrAlreadyExists} {
					if errors.Is(err, sentinel) {
						t.Errorf("error = %v, want no sentinel for status %d", err, tc.status)
					}
				}
				if !strings.HasPrefix(err.Error(), "kubernetes: ") || !strings.HasSuffix(err.Error(), ": "+tc.text) {
					t.Errorf("error = %q, want kubernetes: <call>: %s", err, tc.text)
				}
			})
		}
	}
}

// The error names the call, so a log line says which request failed.
func TestJobClient_ErrorNamesTheCall(t *testing.T) {
	client, _ := newFakeJobAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	want := map[string]string{
		"GetPlexdHook": `kubernetes: get plexdhook "nightly-backup" in "plexd-system": status 403: kubernetes: unauthorized`,
		"CreateJob":    `kubernetes: create job in "plexd-system": status 403: kubernetes: unauthorized`,
		"GetJob":       `kubernetes: get job "` + testJobName + `" in "plexd-system": status 403: kubernetes: unauthorized`,
		"DeleteJob":    `kubernetes: delete job "` + testJobName + `" in "plexd-system": status 403: kubernetes: unauthorized`,
		"ListJobPods":  `kubernetes: list pods of job "` + testJobName + `" in "plexd-system": status 403: kubernetes: unauthorized`,
		"PodLog":       `kubernetes: read log of pod "` + testJobName + `-x7k2p" in "plexd-system": status 403: kubernetes: unauthorized`,
	}
	for _, c := range jobClientCalls {
		err := c.call(client)
		if err == nil || err.Error() != want[c.name] {
			t.Errorf("%s error = %v\nwant              %s", c.name, err, want[c.name])
		}
	}
}

func TestStatusMessage(t *testing.T) {
	long := strings.Repeat("a", 600)
	// The 512th byte is the first of a two-byte rune.
	straddling := strings.Repeat("a", 511) + "é" + "tail"

	for _, tc := range []struct {
		name, body, want string
	}{
		{name: "status", body: `{"kind":"Status","message":"admission webhook denied the request"}`, want: "admission webhook denied the request"},
		{name: "status without message", body: `{"kind":"Status","status":"Failure"}`, want: ""},
		{name: "not a status", body: `{"kind":"Job","message":"x"}`, want: ""},
		{name: "no kind", body: `{"message":"x"}`, want: ""},
		{name: "not JSON", body: "upstream connect error", want: ""},
		{name: "empty", body: "", want: ""},
		{name: "long message", body: `{"kind":"Status","message":"` + long + `"}`, want: long[:512]},
		{name: "rune across the limit", body: `{"kind":"Status","message":"` + straddling + `"}`, want: strings.Repeat("a", 511)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := statusMessage(strings.NewReader(tc.body))
			if got != tc.want {
				t.Errorf("statusMessage = %q (%d bytes), want %q (%d bytes)", got, len(got), tc.want, len(tc.want))
			}
			if !utf8.ValidString(got) {
				t.Errorf("statusMessage = %q, want valid UTF-8", got)
			}
		})
	}
}

// The FailureTarget condition comes ahead of Failed while the pods still
// terminate, so it does not end the Job; a condition that is not True does
// not count.
func TestJobClient_GetJobConditions(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		want         JobState
	}{
		{name: "no status", status: `{}`},
		{name: "no conditions", status: `{"status":{"active":1}}`},
		{
			name:   "failure target only",
			status: `{"status":{"conditions":[{"type":"FailureTarget","status":"True","reason":"BackoffLimitExceeded","message":"Job has reached the specified backoff limit"}]}}`,
		},
		{
			name: "failed",
			status: `{"status":{"conditions":[
				{"type":"FailureTarget","status":"True","reason":"BackoffLimitExceeded","message":"Job has reached the specified backoff limit"},
				{"type":"Failed","status":"True","reason":"BackoffLimitExceeded","message":"Job has reached the specified backoff limit"}
			]}}`,
			want: JobState{Failed: true, Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit"},
		},
		{
			name:   "deadline exceeded",
			status: `{"status":{"conditions":[{"type":"Failed","status":"True","reason":"DeadlineExceeded","message":"Job was active longer than specified deadline"}]}}`,
			want:   JobState{Failed: true, Reason: "DeadlineExceeded", Message: "Job was active longer than specified deadline"},
		},
		{
			name:   "complete",
			status: `{"status":{"conditions":[{"type":"SuccessCriteriaMet","status":"True"},{"type":"Complete","status":"True"}]}}`,
			want:   JobState{Complete: true},
		},
		{
			name:   "condition not true",
			status: `{"status":{"conditions":[{"type":"Failed","status":"False","reason":"BackoffLimitExceeded"}]}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newFakeJobAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tc.status)
			})
			state, err := client.GetJob(context.Background(), "plexd-system", testJobName)
			if err != nil {
				t.Fatalf("GetJob: %v", err)
			}
			if state != tc.want {
				t.Errorf("GetJob = %+v, want %+v", state, tc.want)
			}
		})
	}
}

// The API server cuts a log at limitBytes; one that does not is cut by the
// read.
func TestJobClient_PodLogReadsAtMostLimit(t *testing.T) {
	client, _ := newFakeJobAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 100))
	})

	text, err := client.PodLog(context.Background(), "plexd-system", "pod", 10)
	if err != nil {
		t.Fatalf("PodLog: %v", err)
	}
	if text != strings.Repeat("x", 10) {
		t.Errorf("PodLog = %q, want the first 10 bytes", text)
	}
}

func TestJobClient_UndecodableResponse(t *testing.T) {
	client, _ := newFakeJobAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"items":[`)
	})

	for _, c := range jobClientCalls {
		switch c.name {
		case "GetPlexdHook", "GetJob", "ListJobPods":
		default:
			continue
		}
		err := c.call(client)
		if err == nil || !strings.Contains(err.Error(), "decode response") {
			t.Errorf("%s error = %v, want a decode error", c.name, err)
		}
	}
}

func TestJobClient_MissingTokenSendsNothing(t *testing.T) {
	var requests atomic.Int32
	client, tokenPath := newFakeJobAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, `{}`)
	})
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}

	for _, c := range jobClientCalls {
		err := c.call(client)
		var pathErr *fs.PathError
		if !errors.As(err, &pathErr) {
			t.Errorf("%s error = %v, want a wrapped *fs.PathError", c.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), ": read service account token: ") {
			t.Errorf("%s error = %v, want it to say read service account token", c.name, err)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the API server saw %d requests, want none", n)
	}
}

// A transport failure, here the context running out, is wrapped with the
// call's name.
func TestJobClient_ContextDeadline(t *testing.T) {
	client, _ := newFakeJobAPIServer(t, func(_ http.ResponseWriter, r *http.Request) {
		// Stall until the client gives up; the bound only keeps a broken
		// cancellation from hanging the test.
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := client.GetJob(ctx, "plexd-system", testJobName)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if prefix := `kubernetes: get job "` + testJobName + `" in "plexd-system": `; !strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("error = %v, want it to start with %q", err, prefix)
	}
}

// newAPIServer names the cause; each client names itself. The lister's texts
// are the ones it had before the connection moved into apiServer.
func TestNewAPIServer_ErrorsNameTheClient(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not-a-ca.crt")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := &KubernetesEnvironment{InCluster: true, ServiceAccountToken: filepath.Join(dir, "token")}

	for _, tc := range []struct {
		name, host, port, caPath string
		env                      *KubernetesEnvironment
		want                     string
	}{
		{name: "no host", port: "443", caPath: notPEM, env: env, want: "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must both be set"},
		{name: "no token path", host: "10.96.0.1", port: "443", caPath: notPEM, env: &KubernetesEnvironment{InCluster: true}, want: "no service account token path"},
		{name: "CA bundle without a certificate", host: "10.96.0.1", port: "443", caPath: notPEM, env: env, want: "no certificate in cluster CA bundle " + notPEM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newHookLister(tc.host, tc.port, tc.caPath, tc.env); err == nil || err.Error() != "kubernetes: hook lister: "+tc.want {
				t.Errorf("newHookLister error = %v, want %q", err, "kubernetes: hook lister: "+tc.want)
			}
			if _, err := newJobClient(tc.host, tc.port, tc.caPath, tc.env); err == nil || err.Error() != "kubernetes: job client: "+tc.want {
				t.Errorf("newJobClient error = %v, want %q", err, "kubernetes: job client: "+tc.want)
			}
		})
	}

	_, err := newJobClient("10.96.0.1", "443", filepath.Join(dir, "absent.crt"), env)
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) || !strings.HasPrefix(err.Error(), "kubernetes: job client: read cluster CA: ") {
		t.Errorf("newJobClient with a missing CA bundle = %v, want a wrapped *fs.PathError after kubernetes: job client: read cluster CA:", err)
	}
}

// The API server address comes from the variables the kubelet injects into
// every pod; without one of them there is nothing to connect to.
func TestNewInClusterJobClient_RequiresServiceEnv(t *testing.T) {
	env := &KubernetesEnvironment{InCluster: true, ServiceAccountToken: DefaultTokenPath}

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if _, err := NewInClusterJobClient(env); err == nil {
		t.Error("NewInClusterJobClient without KUBERNETES_SERVICE_HOST succeeded, want an error")
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if _, err := NewInClusterJobClient(env); err == nil {
		t.Error("NewInClusterJobClient without KUBERNETES_SERVICE_PORT succeeded, want an error")
	}
}

// The document leaves out command and args when the template has none, and
// writes the false values the Job depends on.
func TestHookJob_JSONKeepsFalseValues(t *testing.T) {
	data, err := json.Marshal(HookJob{
		Spec: HookJobSpec{Template: HookPodTemplate{Spec: HookPodSpec{
			Containers: []HookContainer{{Name: "hook", Image: "img"}},
		}}},
		Metadata: HookJobMetadata{OwnerReferences: []HookJobOwnerReference{{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"blockOwnerDeletion":false`, `"automountServiceAccountToken":false`, `"backoffLimit":0`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("document = %s, want it to carry %s", data, key)
		}
	}
	for _, key := range []string{`"command"`, `"args"`, `"privileged"`, `"readOnlyRootFilesystem"`, `"capabilities"`} {
		if strings.Contains(string(data), key) {
			t.Errorf("document = %s, want no %s", data, key)
		}
	}
}
