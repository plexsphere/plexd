//go:build windows

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/plexsphere/plexd/internal/packaging"
)

// serviceStopWaitHint is what the service tells the SCM to wait for a stop:
// the agent's drain plus five seconds for the process to exit. Without a hint
// the SCM assumes a service that has not stopped within its default window is
// hung and kills it mid-drain.
const serviceStopWaitHint = drainTimeout + 5*time.Second

// eventID is the identifier every plexd event carries. InstallAsEventCreate
// points the source at EventCreate.exe, whose message table renders ids 1 to
// 1000 as the message text, so the id itself carries no meaning here.
const eventID = 1

// eventReporter is the subset of *eventlog.Log the service and its log handler
// use, so both are testable without an Event Log.
type eventReporter interface {
	Info(eid uint32, msg string) error
	Warning(eid uint32, msg string) error
	Error(eid uint32, msg string) error
}

// runAsService runs the agent under the Service Control Manager when the SCM
// started this process, and reports that it did. Started from a console it
// declines, so plexd up stays an ordinary foreground command.
//
// A service has no console, so the agent's output would otherwise be lost:
// before handing over, the log handler is redirected to the Application Event
// Log under source plexd.
func runAsService(run func(context.Context) error) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return true, fmt.Errorf("plexd up: detect windows service: %w", err)
	}
	if !isService {
		return false, nil
	}

	elog, err := eventlog.Open(packaging.DefaultServiceName)
	if err != nil {
		return true, fmt.Errorf("plexd up: open event log: %w", err)
	}
	defer func() { _ = elog.Close() }()

	newLogHandler = func(lvl slog.Level) slog.Handler {
		return newEventLogHandler(elog, lvl)
	}

	if err := svc.Run(packaging.DefaultServiceName, &agentService{run: run, rep: elog}); err != nil {
		return true, fmt.Errorf("plexd up: windows service: %w", err)
	}
	return true, nil
}

// agentService speaks the SCM's status protocol on the agent's behalf. The SCM
// kills a service that does not report a status within roughly 30 seconds of
// start, so Running is reported as soon as the agent is under way rather than
// once it has registered with the control plane.
type agentService struct {
	run func(context.Context) error
	rep eventReporter
}

func (s *agentService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()

	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			// The agent ended without being asked to: a startup failure, or the
			// health listener's deliberate shutdown. Exiting non-zero is what
			// makes the SCM's recovery actions restart it, which is what
			// Restart=always does on Linux.
			changes <- svc.Status{State: svc.StopPending}
			if err != nil {
				_ = s.rep.Error(eventID, "plexd up: "+err.Error())
			} else {
				_ = s.rep.Warning(eventID, "plexd stopped without a stop request")
			}
			return true, 1

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{
					State:    svc.StopPending,
					WaitHint: uint32(serviceStopWaitHint / time.Millisecond),
				}
				cancel()
				if err := <-done; err != nil {
					_ = s.rep.Error(eventID, "plexd up: "+err.Error())
					return true, 1
				}
				return false, 0
			}
		}
	}
}

// eventLogHandler writes slog records to the Windows Event Log. It formats
// through a text handler so an event reads like the daemon's console output,
// minus the timestamp: the Event Log stamps every event itself.
type eventLogHandler struct {
	rep   eventReporter
	level slog.Level

	mu    *sync.Mutex
	buf   *bytes.Buffer
	inner slog.Handler
}

func newEventLogHandler(rep eventReporter, level slog.Level) *eventLogHandler {
	var (
		mu  sync.Mutex
		buf bytes.Buffer
	)
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	return &eventLogHandler{rep: rep, level: level, mu: &mu, buf: &buf, inner: inner}
}

func (h *eventLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *eventLogHandler) Handle(ctx context.Context, rec slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.buf.Reset()
	if err := h.inner.Handle(ctx, rec); err != nil {
		return err
	}
	msg := string(bytes.TrimRight(h.buf.Bytes(), "\n"))

	switch {
	case rec.Level >= slog.LevelError:
		return h.rep.Error(eventID, msg)
	case rec.Level >= slog.LevelWarn:
		return h.rep.Warning(eventID, msg)
	default:
		return h.rep.Info(eventID, msg)
	}
}

func (h *eventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventLogHandler{rep: h.rep, level: h.level, mu: h.mu, buf: h.buf, inner: h.inner.WithAttrs(attrs)}
}

func (h *eventLogHandler) WithGroup(name string) slog.Handler {
	return &eventLogHandler{rep: h.rep, level: h.level, mu: h.mu, buf: h.buf, inner: h.inner.WithGroup(name)}
}
