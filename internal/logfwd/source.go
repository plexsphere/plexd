package logfwd

import (
	"context"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// systemLogWindow is how far back the first collection of a platform log
// source reaches, matching journalctl's --since=60 seconds ago.
const systemLogWindow = 60 * time.Second

// selfLogMarker is the component attribute every logfwd record carries, as
// slog.TextHandler renders it. A platform log source reads back the sink the
// daemon logs to, so a source that forwarded these lines would feed itself:
// once the control plane is unreachable, every failed report warns, the
// warning is collected as new input, the buffer overflows, that warns again,
// and the daemon never goes idle again. The sources that read the daemon's own
// output drop them.
const selfLogMarker = "component=logfwd"

// LogSource collects log entries from a specific source.
type LogSource interface {
	Collect(ctx context.Context) ([]api.LogEntry, error)
}

// LogReporter abstracts the control plane log reporting API.
type LogReporter interface {
	ReportLogs(ctx context.Context, nodeID string, batch api.LogBatch) error
}
