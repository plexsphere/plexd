package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// hookContainerName is the name of the one container of a hook Job's pod.
// ListJobPods reads that container's state and PodLog its log.
const hookContainerName = "hook"

// JobClient runs the Jobs of dispatched PlexdHooks through the Kubernetes API
// server with the pod's ServiceAccount credentials: it reads a PlexdHook,
// creates, reads and deletes a Job, lists the Job's pods and reads a pod's
// log. HookJobRunner is its one user.
type JobClient struct {
	apiServer
}

// NewInClusterJobClient builds a JobClient for the API server a pod reaches
// through the KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT variables,
// trusting the cluster CA at DefaultCACertPath and authenticating with the
// ServiceAccount token at env.ServiceAccountToken, as NewInClusterHookLister
// does. The client carries no overall timeout: the context passed to each
// method bounds the call.
func NewInClusterJobClient(env *KubernetesEnvironment) (*JobClient, error) {
	return newJobClient(os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"), DefaultCACertPath, env)
}

// newJobClient is NewInClusterJobClient with the API server address and the CA
// bundle path supplied, so a test can point it at a fake API server.
func newJobClient(host, port, caPath string, env *KubernetesEnvironment) (*JobClient, error) {
	srv, err := newAPIServer(host, port, caPath, env)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: job client: %w", err)
	}
	return &JobClient{apiServer: *srv}, nil
}

// JobState is what the conditions of a Job say about its end. Both flags are
// false while the Job runs.
type JobState struct {
	// Complete is set by a Complete condition with status True.
	Complete bool
	// Failed is set by a Failed condition with status True.
	Failed bool
	// Reason and Message are those of the condition that set a flag, such as
	// BackoffLimitExceeded or DeadlineExceeded for a failed Job.
	Reason  string
	Message string
}

// JobPod is what the runner needs of one pod of a Job.
type JobPod struct {
	Name      string
	CreatedAt time.Time
	// ExitCode is the hook container's exit code; nil until it terminated.
	ExitCode *int
	// WaitingReason is why the hook container waits to start, such as
	// ErrImagePull; empty when it is not waiting.
	WaitingReason string
}

// jobsPath is the collection path of the Jobs in namespace.
func jobsPath(namespace string) string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(namespace) + "/jobs"
}

// GetPlexdHook returns the PlexdHook name in namespace. A hook that does not
// exist wraps ErrNotFound.
func (c *JobClient) GetPlexdHook(ctx context.Context, namespace, name string) (*PlexdHook, error) {
	what := fmt.Sprintf("get plexdhook %q in %q", name, namespace)
	path := fmt.Sprintf(plexdHookListPath, url.PathEscape(namespace)) + "/" + url.PathEscape(name)
	resp, err := c.do(ctx, what, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var item plexdHookItem
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return nil, fmt.Errorf("kubernetes: %s: decode response: %w", what, err)
	}
	hook := item.toPlexdHook()
	return &hook, nil
}

// CreateJob creates job in namespace. A Job of the same name that already
// exists wraps ErrAlreadyExists.
func (c *JobClient) CreateJob(ctx context.Context, namespace string, job *HookJob) error {
	what := fmt.Sprintf("create job in %q", namespace)
	body, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("kubernetes: %s: encode job: %w", what, err)
	}
	resp, err := c.do(ctx, what, http.MethodPost, jobsPath(namespace), "", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// GetJob returns the state of the Job name in namespace. A Job that does not
// exist wraps ErrNotFound.
//
// Only the Complete and Failed conditions with status True count. The
// FailureTarget condition the Job controller sets ahead of Failed is ignored:
// the Job's pods may still be terminating then, and Failed follows once they
// are gone.
func (c *JobClient) GetJob(ctx context.Context, namespace, name string) (JobState, error) {
	what := fmt.Sprintf("get job %q in %q", name, namespace)
	resp, err := c.do(ctx, what, http.MethodGet, jobsPath(namespace)+"/"+url.PathEscape(name), "", nil)
	if err != nil {
		return JobState{}, err
	}
	defer resp.Body.Close()

	var job struct {
		Status struct {
			Conditions []struct {
				Type    string `json:"type"`
				Status  string `json:"status"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"conditions"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return JobState{}, fmt.Errorf("kubernetes: %s: decode response: %w", what, err)
	}

	var state JobState
	for _, cond := range job.Status.Conditions {
		if cond.Status != "True" {
			continue
		}
		switch cond.Type {
		case "Complete":
			state.Complete = true
		case "Failed":
			state.Failed = true
		default:
			continue
		}
		state.Reason, state.Message = cond.Reason, cond.Message
	}
	return state, nil
}

// DeleteJob deletes the Job name in namespace and, through background
// propagation, its pods. A Job that is already gone is not an error.
func (c *JobClient) DeleteJob(ctx context.Context, namespace, name string) error {
	what := fmt.Sprintf("delete job %q in %q", name, namespace)
	body := []byte(`{"propagationPolicy":"Background"}`)
	resp, err := c.do(ctx, what, http.MethodDelete, jobsPath(namespace)+"/"+url.PathEscape(name), "", body)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ListJobPods returns the pods of the Job jobName in namespace, selected by
// the job-name label the Job controller sets on them, or an empty slice when
// there are none.
func (c *JobClient) ListJobPods(ctx context.Context, namespace, jobName string) ([]JobPod, error) {
	what := fmt.Sprintf("list pods of job %q in %q", jobName, namespace)
	query := url.Values{"labelSelector": {"job-name=" + jobName}}.Encode()
	resp, err := c.do(ctx, what, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/pods", query, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var list struct {
		Items []struct {
			Metadata struct {
				Name              string    `json:"name"`
				CreationTimestamp time.Time `json:"creationTimestamp"`
			} `json:"metadata"`
			Status struct {
				ContainerStatuses []struct {
					Name  string `json:"name"`
					State struct {
						Waiting *struct {
							Reason string `json:"reason"`
						} `json:"waiting"`
						Terminated *struct {
							ExitCode int `json:"exitCode"`
						} `json:"terminated"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("kubernetes: %s: decode response: %w", what, err)
	}

	pods := make([]JobPod, 0, len(list.Items))
	for _, item := range list.Items {
		pod := JobPod{Name: item.Metadata.Name, CreatedAt: item.Metadata.CreationTimestamp}
		for _, cs := range item.Status.ContainerStatuses {
			if cs.Name != hookContainerName {
				continue
			}
			if t := cs.State.Terminated; t != nil {
				exitCode := t.ExitCode
				pod.ExitCode = &exitCode
			}
			if w := cs.State.Waiting; w != nil {
				pod.WaitingReason = w.Reason
			}
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

// PodLog returns the log of the hook container of pod in namespace, at most
// its first limitBytes bytes. The API server cuts the log there already; the
// read is bounded the same way so a server that ignores the limit cannot hand
// over more.
func (c *JobClient) PodLog(ctx context.Context, namespace, pod string, limitBytes int64) (string, error) {
	what := fmt.Sprintf("read log of pod %q in %q", pod, namespace)
	query := url.Values{
		"container":  {hookContainerName},
		"limitBytes": {strconv.FormatInt(limitBytes, 10)},
	}.Encode()
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(pod) + "/log"
	resp, err := c.do(ctx, what, http.MethodGet, path, query, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	text, err := io.ReadAll(io.LimitReader(resp.Body, limitBytes))
	if err != nil {
		return "", fmt.Errorf("kubernetes: %s: read response: %w", what, err)
	}
	return string(text), nil
}

// HookJob is a batch/v1 Job as HookJobRunner creates it for one run of a
// PlexdHook. It holds only the fields that Job sets, with the JSON names of
// the batch/v1 API.
type HookJob struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   HookJobMetadata `json:"metadata"`
	Spec       HookJobSpec     `json:"spec"`
}

// HookJobMetadata is the Job's object metadata.
type HookJobMetadata struct {
	Name            string                  `json:"name"`
	Labels          map[string]string       `json:"labels"`
	Annotations     map[string]string       `json:"annotations"`
	OwnerReferences []HookJobOwnerReference `json:"ownerReferences"`
}

// HookJobOwnerReference names the PlexdHook that owns the Job. Both flags are
// always written, so the API server never fills in a default for
// blockOwnerDeletion.
type HookJobOwnerReference struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	UID                string `json:"uid"`
	Controller         bool   `json:"controller"`
	BlockOwnerDeletion bool   `json:"blockOwnerDeletion"`
}

// HookJobSpec is the Job's spec.
type HookJobSpec struct {
	BackoffLimit            int32           `json:"backoffLimit"`
	ActiveDeadlineSeconds   int64           `json:"activeDeadlineSeconds"`
	TTLSecondsAfterFinished int32           `json:"ttlSecondsAfterFinished"`
	Template                HookPodTemplate `json:"template"`
}

// HookPodTemplate is the template of the Job's pod.
type HookPodTemplate struct {
	Metadata HookPodMetadata `json:"metadata"`
	Spec     HookPodSpec     `json:"spec"`
}

// HookPodMetadata is the object metadata of the Job's pod.
type HookPodMetadata struct {
	Labels map[string]string `json:"labels"`
}

// HookPodSpec is the spec of the Job's pod. automountServiceAccountToken is
// always written, because false is the value that matters.
type HookPodSpec struct {
	RestartPolicy                string           `json:"restartPolicy"`
	AutomountServiceAccountToken bool             `json:"automountServiceAccountToken"`
	Tolerations                  []HookToleration `json:"tolerations"`
	Affinity                     HookAffinity     `json:"affinity"`
	Containers                   []HookContainer  `json:"containers"`
}

// HookToleration is one toleration of the Job's pod.
type HookToleration struct {
	Operator string `json:"operator"`
}

// HookAffinity is the affinity of the Job's pod.
type HookAffinity struct {
	NodeAffinity HookNodeAffinity `json:"nodeAffinity"`
}

// HookNodeAffinity holds the node selector the Job's pod must match.
type HookNodeAffinity struct {
	RequiredDuringSchedulingIgnoredDuringExecution HookNodeSelector `json:"requiredDuringSchedulingIgnoredDuringExecution"`
}

// HookNodeSelector is a node selector, met when any of its terms is.
type HookNodeSelector struct {
	NodeSelectorTerms []HookNodeSelectorTerm `json:"nodeSelectorTerms"`
}

// HookNodeSelectorTerm is one node selector term, met when all of its field
// requirements are.
type HookNodeSelectorTerm struct {
	MatchFields []HookNodeSelectorRequirement `json:"matchFields"`
}

// HookNodeSelectorRequirement is one requirement on a field of a Node.
type HookNodeSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// HookContainer is the one container of the Job's pod. Command and Args are
// left out when empty, so the image's entrypoint and arguments apply.
type HookContainer struct {
	Name            string              `json:"name"`
	Image           string              `json:"image"`
	Command         []string            `json:"command,omitempty"`
	Args            []string            `json:"args,omitempty"`
	Env             []HookEnvVar        `json:"env"`
	SecurityContext HookSecurityContext `json:"securityContext"`
}

// HookEnvVar is one environment variable of the hook container.
type HookEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HookSecurityContext is the hook container's security context: privileged,
// or a read-only root filesystem with every capability dropped. A field that is
// not set is left out, so each of the two shapes carries only its own keys.
type HookSecurityContext struct {
	Privileged             bool              `json:"privileged,omitempty"`
	ReadOnlyRootFilesystem bool              `json:"readOnlyRootFilesystem,omitempty"`
	Capabilities           *HookCapabilities `json:"capabilities,omitempty"`
}

// HookCapabilities lists the capabilities the hook container drops.
type HookCapabilities struct {
	Drop []string `json:"drop"`
}
