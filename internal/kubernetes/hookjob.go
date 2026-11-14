package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/plexsphere/plexd/internal/actions"
)

// hookJobPollInterval is how often Wait reads the Job's status. At most
// actions.max_concurrent runs exist at a time, so the API server sees one GET
// per run every interval.
const hookJobPollInterval = 2 * time.Second

// hookJobBackstop is how long after the run's deadline the Job's
// activeDeadlineSeconds ends it. plexd enforces the deadline itself; the
// backstop ends a Job whose deadline passes with no agent running.
const hookJobBackstop = 30 * time.Second

// hookJobRequestTimeout bounds each API server call, so one unanswered call
// cannot hold a run past its deadline.
const hookJobRequestTimeout = 10 * time.Second

// hookJobTTLSeconds is how long a finished Job stays, so its pod can be
// inspected, and so an agent that restarts before its report landed still
// finds the outcome.
const hookJobTTLSeconds = 3600

// hookJobManagedBy is the app.kubernetes.io/managed-by label of a hook Job and
// its pod. The pod carries no app.kubernetes.io/name: the DaemonSet selects
// its own pods on that label.
const hookJobManagedBy = "plexd"

// hookJobAPI is the part of JobClient HookJobRunner uses.
type hookJobAPI interface {
	GetPlexdHook(ctx context.Context, namespace, name string) (*PlexdHook, error)
	CreateJob(ctx context.Context, namespace string, job *HookJob) error
	GetJob(ctx context.Context, namespace, name string) (JobState, error)
	DeleteJob(ctx context.Context, namespace, name string) error
	ListJobPods(ctx context.Context, namespace, jobName string) ([]JobPod, error)
	PodLog(ctx context.Context, namespace, pod string, limitBytes int64) (string, error)
}

var _ actions.PlexdHookRunner = (*HookJobRunner)(nil)

// HookJobConfig is what a HookJobRunner needs to know of the agent it runs in.
type HookJobConfig struct {
	// Namespace is the ServiceAccount's namespace. The runner reads PlexdHooks
	// and creates Jobs there.
	Namespace string
	// NodeName is the Kubernetes node the agent runs on, from MY_NODE_NAME.
	// Every Job is pinned to it.
	NodeName string
	// NodeID is plexd's node id.
	NodeID string
	// OutputLimit is actions.max_output_bytes.
	OutputLimit int64
}

// HookJobRunner runs a dispatched PlexdHook as one Kubernetes Job per
// execution, on the agent's own node, and follows the Job to its end. It
// implements actions.PlexdHookRunner.
//
// The Job is named after the node id and the execution id together, so Start,
// Wait and Stop find the same Job from the execution id alone, in this agent
// process or the next one, and two agents that receive the same execution id
// for a cohort dispatch create two Jobs.
type HookJobRunner struct {
	client hookJobAPI
	cfg    HookJobConfig
	logger *slog.Logger

	// The constants of the same names, held here so a test can shorten them.
	pollInterval   time.Duration
	backstop       time.Duration
	requestTimeout time.Duration
	ttlSeconds     int32
}

// NewHookJobRunner returns a HookJobRunner that reaches the API server through
// client.
func NewHookJobRunner(client hookJobAPI, cfg HookJobConfig, logger *slog.Logger) *HookJobRunner {
	return &HookJobRunner{
		client:         client,
		cfg:            cfg,
		logger:         logger.With("component", "plexdhook-jobs"),
		pollInterval:   hookJobPollInterval,
		backstop:       hookJobBackstop,
		requestTimeout: hookJobRequestTimeout,
		ttlSeconds:     hookJobTTLSeconds,
	}
}

// hookJobName is the name of the Job of one execution on one node: plexdhook-
// and the first 32 hex characters of the SHA-256 over the node id, a zero byte
// and the execution id. An execution id names the Execution, not its target,
// so every agent of a cohort dispatch receives the same one; the node id keeps
// their Jobs apart. The hash is a valid DNS label whatever either id holds.
func hookJobName(nodeID, executionID string) string {
	sum := sha256.Sum256([]byte(nodeID + "\x00" + executionID))
	return "plexdhook-" + hex.EncodeToString(sum[:])[:32]
}

// hookParamSanitizer matches every character an environment variable name
// cannot carry.
var hookParamSanitizer = regexp.MustCompile(`[^A-Za-z0-9_]`)

// sanitizeHookParamName converts a parameter name to an environment variable
// suffix: upper case, with every other character but a digit or an underscore
// replaced by an underscore.
func sanitizeHookParamName(name string) string {
	return strings.ToUpper(hookParamSanitizer.ReplaceAllString(name, "_"))
}

// ceilSeconds is d in whole seconds, rounded up, and 0 for a d that is not
// positive.
func ceilSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}

// Start reads the PlexdHook run.Hook names and creates the run's Job from it.
// A Job that already exists is not an error: it is this run's, created by an
// earlier attempt.
//
// A hook that does not exist returns actions.ErrPlexdHookNotFound. A hook
// whose image is not pinned by a sha256 digest is refused without a Job, as
// the capability manifest leaves it out; so is a parameter with a NUL in its
// name or value, which no process environment can carry.
func (r *HookJobRunner) Start(ctx context.Context, run actions.PlexdHookRun) error {
	hook, err := withRequestTimeout(ctx, r.requestTimeout, func(ctx context.Context) (*PlexdHook, error) {
		return r.client.GetPlexdHook(ctx, r.cfg.Namespace, run.Hook)
	})
	if errors.Is(err, ErrNotFound) {
		return actions.ErrPlexdHookNotFound
	}
	if err != nil {
		return fmt.Errorf("get plexd hook: %w", err)
	}
	if _, ok := hook.Spec.ImageDigest(); !ok {
		return fmt.Errorf("plexd hook image is not pinned by a sha256 digest: %s", hook.Spec.Image())
	}
	env, err := hookJobEnv(r.cfg.NodeID, run, hook.Spec)
	if err != nil {
		return err
	}

	job := r.buildJob(hook, run, env)
	_, err = withRequestTimeout(ctx, r.requestTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, r.client.CreateJob(ctx, r.cfg.Namespace, job)
	})
	if err != nil && !errors.Is(err, ErrAlreadyExists) {
		return fmt.Errorf("create job: %w", err)
	}

	r.logger.Info("plexd hook job created",
		"execution_id", run.ExecutionID,
		"hook", run.Hook,
		"job", job.Metadata.Name,
		"deadline_seconds", ceilSeconds(run.Deadline),
	)
	return nil
}

// hookJobEnv builds the hook container's environment: PLEXD_NODE_ID,
// PLEXD_EXECUTION_ID and PLEXD_HOOK_NAME, then one PLEXD_PARAM_<NAME> per
// parameter. The resource's parameters are written in list order, then the
// dispatch's in ascending name order, and a later write to the same variable
// wins, so a dispatch parameter overrides the resource's default of the same
// name. The variables come back sorted by name, so the same run always gives
// the same Job.
func hookJobEnv(nodeID string, run actions.PlexdHookRun, spec PlexdHookSpec) ([]HookEnvVar, error) {
	vars := map[string]string{
		"PLEXD_NODE_ID":      nodeID,
		"PLEXD_EXECUTION_ID": run.ExecutionID,
		"PLEXD_HOOK_NAME":    spec.HookName,
	}
	set := func(name, value string) error {
		if strings.ContainsRune(name, 0) || strings.ContainsRune(value, 0) {
			// The name is printed with its NUL spelled out: the error becomes
			// the execution callback's, and the control plane's text columns
			// cannot hold a NUL either.
			return fmt.Errorf("plexd hook parameter %s contains a NUL character", strings.ReplaceAll(name, "\x00", `\x00`))
		}
		vars["PLEXD_PARAM_"+sanitizeHookParamName(name)] = value
		return nil
	}
	for _, p := range spec.Parameters {
		if err := set(p.Name, p.Value); err != nil {
			return nil, err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(run.Parameters)) {
		if err := set(name, run.Parameters[name]); err != nil {
			return nil, err
		}
	}

	env := make([]HookEnvVar, 0, len(vars))
	for _, name := range slices.Sorted(maps.Keys(vars)) {
		env = append(env, HookEnvVar{Name: name, Value: vars[name]})
	}
	return env, nil
}

// buildJob is the Job of one run of hook. Its pod runs on cfg.NodeName,
// whatever taints it carries, mounts no ServiceAccount token, and is never
// restarted. activeDeadlineSeconds is the run's deadline plus the backstop.
//
// DECISION: the owner reference sets blockOwnerDeletion false. true needs
// update on plexdhooks/finalizers on clusters that enforce owner-reference
// permissions, and background garbage collection does not need it.
func (r *HookJobRunner) buildJob(hook *PlexdHook, run actions.PlexdHookRun, env []HookEnvVar) *HookJob {
	container := HookContainer{
		Name:  hookContainerName,
		Image: hook.Spec.Image(),
		Env:   env,
	}
	if jt := hook.Spec.JobTemplate; jt != nil {
		container.Command = jt.Command
		container.Args = jt.Args
	}
	if hook.Spec.Privileged {
		container.SecurityContext = HookSecurityContext{Privileged: true}
	} else {
		container.SecurityContext = HookSecurityContext{
			ReadOnlyRootFilesystem: true,
			Capabilities:           &HookCapabilities{Drop: []string{"ALL"}},
		}
	}

	return &HookJob{
		APIVersion: "batch/v1",
		Kind:       "Job",
		Metadata: HookJobMetadata{
			Name:   hookJobName(r.cfg.NodeID, run.ExecutionID),
			Labels: map[string]string{"app.kubernetes.io/managed-by": hookJobManagedBy},
			Annotations: map[string]string{
				"plexd.plexsphere.com/execution-id": run.ExecutionID,
				"plexd.plexsphere.com/node-id":      r.cfg.NodeID,
				"plexd.plexsphere.com/hook":         hook.Name,
			},
			OwnerReferences: []HookJobOwnerReference{{
				APIVersion:         "plexd.plexsphere.com/v1alpha1",
				Kind:               "PlexdHook",
				Name:               hook.Name,
				UID:                hook.UID,
				Controller:         true,
				BlockOwnerDeletion: false,
			}},
		},
		Spec: HookJobSpec{
			BackoffLimit:            0,
			ActiveDeadlineSeconds:   ceilSeconds(run.Deadline) + ceilSeconds(r.backstop),
			TTLSecondsAfterFinished: r.ttlSeconds,
			Template: HookPodTemplate{
				Metadata: HookPodMetadata{
					Labels: map[string]string{"app.kubernetes.io/managed-by": hookJobManagedBy},
				},
				Spec: HookPodSpec{
					RestartPolicy:                "Never",
					AutomountServiceAccountToken: false,
					Tolerations:                  []HookToleration{{Operator: "Exists"}},
					Affinity: HookAffinity{NodeAffinity: HookNodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: HookNodeSelector{
							NodeSelectorTerms: []HookNodeSelectorTerm{{
								MatchFields: []HookNodeSelectorRequirement{{
									Key:      "metadata.name",
									Operator: "In",
									Values:   []string{r.cfg.NodeName},
								}},
							}},
						},
					}},
					Containers: []HookContainer{container},
				},
			},
		},
	}
}

// Wait follows the run's Job until it is over and returns its outcome. It
// reads the Job's status at once and then every poll interval:
//
//   - Complete: the run succeeded, with the hook container's exit code and log.
//   - Failed with reason DeadlineExceeded: the backstop ended the Job, which
//     deleted its pods with their log, so the run timed out with neither.
//   - Failed otherwise: the run failed, with the exit code and log when the
//     container terminated, or the Job's reason and message when it did not.
//   - Gone: actions.ErrPlexdHookJobNotFound.
//   - Unreadable: logged once per streak of failed reads, and read again.
//
// When bound has passed since Wait began, it reads the Job's status once more,
// so a Job that ended since the last read is reported as it ended, and then
// reads what log there is, deletes the Job and returns a timed-out run, saying
// so when the hook container never started. When ctx ends first it returns
// ctx.Err() and leaves the Job alone: the agent is going away or the run was
// cancelled, and either way the caller decides what becomes of the Job.
//
// The same holds when ctx ends while Wait reads the outcome of a Job it found
// over, or deletes one whose bound passed: a read or a delete that ctx cut
// short returns ctx.Err() rather than a result missing its exit code or its
// log, and the caller stops the Job or leaves it for the next agent.
func (r *HookJobRunner) Wait(ctx context.Context, executionID string, bound time.Duration) (actions.PlexdHookResult, error) {
	name := hookJobName(r.cfg.NodeID, executionID)
	expired := time.NewTimer(bound)
	defer expired.Stop()
	poll := time.NewTimer(r.pollInterval)
	defer poll.Stop()

	failing := false
	pastBound := false
	for {
		state, err := withRequestTimeout(ctx, r.requestTimeout, func(ctx context.Context) (JobState, error) {
			return r.client.GetJob(ctx, r.cfg.Namespace, name)
		})
		switch {
		case err != nil && ctx.Err() != nil:
			return actions.PlexdHookResult{}, ctx.Err()
		case errors.Is(err, ErrNotFound):
			return actions.PlexdHookResult{}, actions.ErrPlexdHookJobNotFound
		case err != nil:
			if !failing {
				r.logger.Warn("plexd hook job status read failed",
					"execution_id", executionID,
					"job", name,
					"error", err,
				)
			}
			failing = true
		case state.Complete:
			res, _, _, err := r.collect(ctx, executionID, name)
			if err != nil && ctx.Err() != nil {
				return actions.PlexdHookResult{}, ctx.Err()
			}
			res.Succeeded = true
			return res, nil
		case state.Failed && state.Reason == "DeadlineExceeded":
			return actions.PlexdHookResult{TimedOut: true}, nil
		case state.Failed:
			res, _, _, err := r.collect(ctx, executionID, name)
			if err != nil && ctx.Err() != nil {
				return actions.PlexdHookResult{}, ctx.Err()
			}
			if res.ExitCode == nil {
				res.Reason = jobFailedReason(state)
			}
			return res, nil
		default:
			failing = false
		}

		if pastBound {
			return r.timeOut(ctx, executionID, name)
		}

		select {
		case <-ctx.Done():
			return actions.PlexdHookResult{}, ctx.Err()
		case <-expired.C:
			// Both may be ready at once; an ended ctx still leaves the Job
			// alone.
			if err := ctx.Err(); err != nil {
				return actions.PlexdHookResult{}, err
			}
			// The last read may be up to a poll interval old, so the Job is
			// read once more before it is timed out: a hook that finished in
			// that interval did not time out.
			pastBound = true
		case <-poll.C:
			poll.Reset(r.pollInterval)
		}
	}
}

// jobFailedReason says why a failed Job's container left no exit code, from
// the Job's Failed condition.
func jobFailedReason(state JobState) string {
	reason := "plexd hook job failed"
	if state.Reason != "" {
		reason += ": " + state.Reason
	}
	if state.Message != "" {
		reason += ": " + state.Message
	}
	return reason
}

// timeOut ends a run whose bound passed: it reads what log there is, deletes
// the Job and returns the run as timed out. When the hook container never
// started, the result says so, with the reason it waits for when there is one,
// such as ErrImagePull. A failed delete is logged and otherwise left to the
// Job's activeDeadlineSeconds, which ends it shortly after.
//
// A hook container that has terminated by the time its pod is read finished
// after the last status read, so the run is reported with its exit code and
// log, and the Job is left to its ttlSecondsAfterFinished like any finished
// one. A read or a delete that ctx cut short returns ctx.Err(), as Wait does.
func (r *HookJobRunner) timeOut(ctx context.Context, executionID, name string) (actions.PlexdHookResult, error) {
	res, pod, listed, err := r.collect(ctx, executionID, name)
	if err != nil && ctx.Err() != nil {
		return actions.PlexdHookResult{}, ctx.Err()
	}
	if res.ExitCode != nil {
		res.Succeeded = *res.ExitCode == 0
		return res, nil
	}
	if err := r.deleteJob(ctx, name); err != nil {
		if ctx.Err() != nil {
			return actions.PlexdHookResult{}, ctx.Err()
		}
		r.logger.Warn("plexd hook job delete failed",
			"execution_id", executionID,
			"job", name,
			"error", err,
		)
	}
	res.TimedOut = true
	// Pods that could not be listed say nothing about whether the container
	// started.
	if listed {
		switch {
		case pod == nil:
			res.Reason = "hook container never started"
		case pod.WaitingReason != "":
			res.Reason = "hook container never started: " + pod.WaitingReason
		}
	}
	return res, nil
}

// Stop reads the log of the run's Job so far and deletes the Job. A Job
// without a pod gives an empty log. A failed delete is returned with the log
// that was read.
//
// The log read gets at most half of what is left of ctx, so an API server
// that is slow to answer it cannot spend the time the delete needs: a Stop
// that does not delete leaves the hook running until the Job's backstop.
func (r *HookJobRunner) Stop(ctx context.Context, executionID string) (string, error) {
	name := hookJobName(r.cfg.NodeID, executionID)
	readCtx, cancelRead := context.WithTimeout(ctx, halfOfWhatIsLeft(ctx, r.requestTimeout))
	res, _, _, _ := r.collect(readCtx, executionID, name)
	cancelRead()
	if err := r.deleteJob(ctx, name); err != nil {
		return res.Output, fmt.Errorf("delete job: %w", err)
	}
	return res.Output, nil
}

// halfOfWhatIsLeft is half the time left until ctx's deadline, or fallback
// when ctx has none.
func halfOfWhatIsLeft(ctx context.Context, fallback time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fallback
	}
	return time.Until(deadline) / 2
}

// collect reads the outcome a Job's pods hold: the newest pod's hook
// container exit code and its log, read with a limit one byte over
// cfg.OutputLimit so the executor sees that a longer log was cut. It returns
// the newest pod, nil when the Job has none, whether the pods could be listed
// at all, and the error of a failed list or log read, which is also logged
// and yields no output.
func (r *HookJobRunner) collect(ctx context.Context, executionID, name string) (res actions.PlexdHookResult, newest *JobPod, listed bool, err error) {
	pods, err := withRequestTimeout(ctx, r.requestTimeout, func(ctx context.Context) ([]JobPod, error) {
		return r.client.ListJobPods(ctx, r.cfg.Namespace, name)
	})
	if err != nil {
		r.logger.Warn("plexd hook output unavailable",
			"execution_id", executionID,
			"job", name,
			"error", err,
		)
		return res, nil, false, err
	}
	for i := range pods {
		if newest == nil || pods[i].CreatedAt.After(newest.CreatedAt) {
			newest = &pods[i]
		}
	}
	if newest == nil {
		return res, nil, true, nil
	}
	res.ExitCode = newest.ExitCode

	output, err := withRequestTimeout(ctx, r.requestTimeout, func(ctx context.Context) (string, error) {
		return r.client.PodLog(ctx, r.cfg.Namespace, newest.Name, r.cfg.OutputLimit+1)
	})
	if err != nil {
		r.logger.Warn("plexd hook output unavailable",
			"execution_id", executionID,
			"job", name,
			"pod", newest.Name,
			"error", err,
		)
		return res, newest, true, err
	}
	res.Output = output
	return res, newest, true, nil
}

// deleteJob deletes the Job name under the request timeout.
func (r *HookJobRunner) deleteJob(ctx context.Context, name string) error {
	_, err := withRequestTimeout(ctx, r.requestTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, r.client.DeleteJob(ctx, r.cfg.Namespace, name)
	})
	return err
}

// withRequestTimeout runs one API server call under a context of its own that
// ends after timeout, or with ctx.
func withRequestTimeout[T any](ctx context.Context, timeout time.Duration, call func(context.Context) (T, error)) (T, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return call(callCtx)
}
