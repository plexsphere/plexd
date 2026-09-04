//go:build windows

package logfwd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"unsafe"

	"golang.org/x/sys/windows"
)

// x/sys/windows carries no binding for the Event Log query API, so the four
// procedures are resolved from wevtapi at first use. NewLazySystemDLL loads
// the library from System32 only, which keeps a DLL of the same name next to
// the binary out of the search path.
var (
	modwevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modwevtapi.NewProc("EvtQuery")
	procEvtNext   = modwevtapi.NewProc("EvtNext")
	procEvtRender = modwevtapi.NewProc("EvtRender")
	procEvtClose  = modwevtapi.NewProc("EvtClose")
)

const (
	// EvtQueryChannelPath reads Path as a channel name rather than a log file,
	// EvtQueryForwardDirection walks the result oldest event first, and
	// EvtRenderEventXml renders an event handle as the XML parseEventXML reads.
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtRenderEventXML        = 1

	eventLogChannel   = "Application"
	eventLogMaxEvents = 1000 // Per read, matching journalctl's -n 1000.
	eventLogBatch     = 64   // Handles requested per EvtNext call.
	// Code units the render buffer starts at. 4 KiB of text holds the XML of
	// an ordinary event, so a render rarely has to grow it.
	eventLogRenderBuf = 2048
	// EvtNext waits this long for the result set to produce the next batch.
	// The events are already written when the read starts, so the timeout only
	// bounds a call that would otherwise hang.
	eventLogNextTimeoutMS = 1000
)

// WevtapiReader implements EventLogReader over the Windows Event Log API. It
// keeps the record id of the newest event it returned, so a read never repeats
// an event; the first read reaches back systemLogWindow.
//
// Reading the Application channel needs no privilege beyond the one every
// authenticated user and the LocalSystem account the service runs under
// already have.
//
// The provider name is a label, not an identity. The Application channel's
// default ACL grants write to Interactive Users, and RegisterEventSource takes
// any source name, so an unprivileged local user can write events under
// provider plexd that this reader cannot tell from the service's own. Closing
// that would mean stamping every record the service writes with its SID and
// matching on it here, which changes how the service writes as much as how
// this reads. Until then a forwarded eventlog entry attests that something on
// the host wrote it, not that plexd did.
//
// Clearing the channel at runtime (wevtutil cl Application) is not detected:
// the record ids restart at 1 while the cursor keeps its old value, so the
// reader stays silent until the ids pass it again or plexd restarts.
type WevtapiReader struct {
	channel  string
	provider string
	cursor   uint64
	logger   *slog.Logger
}

// NewWevtapiReader creates a WevtapiReader for the events provider writes to
// the Application channel. logger reports the events a read had to drop.
func NewWevtapiReader(provider string, logger *slog.Logger) *WevtapiReader {
	return &WevtapiReader{
		channel:  eventLogChannel,
		provider: provider,
		logger:   logger,
	}
}

// ReadEvents queries the channel for the events of the reader's provider and
// renders each of them. It returns at most eventLogMaxEvents records, oldest
// first. The cursor moves only when the read succeeds, so a failed read is
// repeated whole in the next cycle instead of losing the events it did not
// return, and an event that cannot be rendered or parsed is dropped alone
// rather than stopping the cursor on it.
func (r *WevtapiReader) ReadEvents(ctx context.Context) ([]EventRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("logfwd: eventlog: %w", err)
	}

	channel, err := windows.UTF16PtrFromString(r.channel)
	if err != nil {
		return nil, fmt.Errorf("logfwd: eventlog: query: %w", err)
	}
	query, err := windows.UTF16PtrFromString(eventLogQuery(r.provider, r.cursor, systemLogWindow))
	if err != nil {
		return nil, fmt.Errorf("logfwd: eventlog: query: %w", err)
	}

	// All four procedures are resolved before the first call so a wevtapi
	// without one of them fails before a handle is open.
	for _, proc := range []*windows.LazyProc{procEvtQuery, procEvtNext, procEvtRender, procEvtClose} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("logfwd: eventlog: %w", err)
		}
	}

	// EvtQuery reports ERROR_EVT_CHANNEL_NOT_FOUND for a channel that does not
	// exist, ERROR_EVT_INVALID_QUERY for an XPath the service rejects and
	// ERROR_ACCESS_DENIED when the process may not read the channel.
	resultSet, _, lastErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(query)),
		evtQueryChannelPath|evtQueryForwardDirection,
	)
	if resultSet == 0 {
		return nil, fmt.Errorf("logfwd: eventlog: EvtQuery: %w", lastErr)
	}
	defer closeEventHandle(resultSet)

	var records []EventRecord
	for len(records) < eventLogMaxEvents {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("logfwd: eventlog: %w", err)
		}

		var handles [eventLogBatch]uintptr
		var returned uint32
		ok, _, lastErr := procEvtNext.Call(
			resultSet,
			eventLogBatch,
			uintptr(unsafe.Pointer(&handles[0])),
			eventLogNextTimeoutMS,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ok == 0 {
			if errors.Is(lastErr, windows.ERROR_NO_MORE_ITEMS) {
				break
			}
			return nil, fmt.Errorf("logfwd: eventlog: EvtNext: %w", lastErr)
		}
		// A successful call without a handle leaves nothing to render and
		// would repeat forever, so it ends the read like an exhausted set.
		if returned == 0 {
			break
		}

		batch := renderEvents(handles[:returned], r.logger)
		// EvtNext hands out whole batches, so the last one can carry more
		// events than the cap leaves room for. The events dropped here are the
		// newest, and the cursor stays below them, so the next read returns
		// them rather than skipping them.
		if room := eventLogMaxEvents - len(records); len(batch) > room {
			batch = batch[:room]
		}
		records = append(records, batch...)
	}

	for _, record := range records {
		if record.RecordID > r.cursor {
			r.cursor = record.RecordID
		}
	}
	return records, nil
}

// renderEvents renders a batch of event handles and closes every one of them,
// a render failure included. An event EvtRender or parseEventXML rejects is
// dropped alone, the way JournalctlReader skips a malformed line, so one
// unreadable event costs neither the batch around it nor every read after it:
// failing the whole read would leave the cursor below that event and stop the
// reader on it for the life of the process.
//
// What a drop costs instead is the event itself: the cursor moves past it with
// the batch around it, so nothing reads it again. That makes the count the
// only trace it leaves, and it is logged rather than kept, since a batch the
// Event Log service could not render (it restarted mid-read, it is out of
// memory) is a host-level condition an operator has to see. The count carries
// the last of the errors behind it, which for those conditions is the same one
// every drop in the batch hit.
//
// The batch shares one render buffer, which an event that does not fit grows
// for the rest of the batch.
func renderEvents(handles []uintptr, logger *slog.Logger) []EventRecord {
	defer func() {
		for _, handle := range handles {
			closeEventHandle(handle)
		}
	}()

	buf := make([]uint16, eventLogRenderBuf)
	records := make([]EventRecord, 0, len(handles))
	var dropped int
	var dropErr error
	for _, handle := range handles {
		text, grown, err := renderEventXML(handle, buf)
		buf = grown
		if err != nil {
			dropped, dropErr = dropped+1, err
			continue
		}
		record, err := parseEventXML([]byte(text))
		if err != nil {
			dropped, dropErr = dropped+1, err
			continue
		}
		records = append(records, record)
	}
	if dropped > 0 {
		// component=logfwd keeps this warning out of the reader's own next
		// read, which would otherwise forward it back as an event.
		logger.Warn("logfwd: eventlog: events dropped, unreadable",
			slog.String("component", "logfwd"),
			slog.Int("dropped", dropped),
			slog.Any("error", dropErr),
		)
	}
	return records
}

// renderEventXML renders one event handle as XML into buf and returns the
// buffer to render the next event into, which is a larger one when this event
// did not fit. EvtRender is an LRPC call into the Event Log service, so
// rendering straight into a buffer that almost always fits halves the round
// trips a size probe in front of every render would cost.
func renderEventXML(handle uintptr, buf []uint16) (string, []uint16, error) {
	for {
		var used, props uint32
		r1, _, lastErr := procEvtRender.Call(
			0,
			handle,
			evtRenderEventXML,
			// used counts bytes, the buffer holds UTF-16 code units.
			uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)),
			uintptr(unsafe.Pointer(&props)),
		)
		if r1 != 0 {
			return windows.UTF16ToString(buf), buf, nil
		}
		// ERROR_INSUFFICIENT_BUFFER puts the size the event needs into used.
		// A size the call already had would render again into the same buffer
		// and never end, so it ends the render like any other failure.
		if !errors.Is(lastErr, windows.ERROR_INSUFFICIENT_BUFFER) || int(used) <= len(buf)*2 {
			return "", buf, fmt.Errorf("logfwd: eventlog: EvtRender: %w", lastErr)
		}
		buf = make([]uint16, (used+1)/2)
	}
}

// closeEventHandle releases an Event Log handle. EvtClose fails only for a
// handle that is not one, which the callers here cannot produce, so its result
// is dropped.
func closeEventHandle(handle uintptr) {
	_, _, _ = procEvtClose.Call(handle)
}
