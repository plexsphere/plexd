package logfwd

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// EventRecord is one event read from a Windows Event Log channel.
type EventRecord struct {
	RecordID  uint64
	Timestamp time.Time
	Level     int // 1 critical, 2 error, 3 warning, 4 information, 5 verbose
	Provider  string
	Message   string
}

// EventLogReader abstracts Windows Event Log access for testability.
type EventLogReader interface {
	ReadEvents(ctx context.Context) ([]EventRecord, error)
}

// EventLogSource implements LogSource by reading the Windows Event Log
// through an EventLogReader.
type EventLogSource struct {
	reader   EventLogReader
	hostname string
}

// NewEventLogSource creates an EventLogSource that reads through reader.
// Entries carry the event's provider as their unit and hostname as their host.
func NewEventLogSource(reader EventLogReader, hostname string) *EventLogSource {
	return &EventLogSource{
		reader:   reader,
		hostname: hostname,
	}
}

// Collect reads the events the reader has and maps them to api.LogEntry
// values. An event whose timestamp the parser could not date is stamped at
// collection time, which keeps it in order with the rest of the batch.
func (s *EventLogSource) Collect(ctx context.Context) ([]api.LogEntry, error) {
	records, err := s.reader.ReadEvents(ctx)
	if err != nil {
		return nil, fmt.Errorf("logfwd: eventlog: %w", err)
	}

	if len(records) == 0 {
		return nil, nil
	}

	entries := make([]api.LogEntry, 0, len(records))
	for _, rec := range records {
		// The service logs through a handler that writes to this same channel,
		// so the forwarder's own diagnostics would come back as input to its
		// next collection.
		if strings.Contains(rec.Message, selfLogMarker) {
			continue
		}
		timestamp := rec.Timestamp
		if timestamp.IsZero() {
			timestamp = time.Now()
		}
		entries = append(entries, api.LogEntry{
			Timestamp: timestamp,
			Source:    "eventlog",
			Unit:      rec.Provider,
			Message:   rec.Message,
			Severity:  levelSeverity(rec.Level),
			Hostname:  s.hostname,
		})
	}
	// Every event in the batch can be one of the forwarder's own, which leaves
	// the same nothing to forward as a batch that held no event at all.
	if len(entries) == 0 {
		return nil, nil
	}
	return entries, nil
}

// levelSeverity maps an Event Log level to a syslog severity. The records the
// service writes through ReportEvent with the information, warning and error
// types render as levels 4, 3 and 2. Level 0 means the publisher left the
// level unset, so it falls back to info along with every level the Event Log
// schema does not define.
func levelSeverity(level int) string {
	switch level {
	case 1:
		return "crit"
	case 2:
		return "err"
	case 3:
		return "warning"
	case 4:
		return "info"
	case 5:
		return "debug"
	default:
		return "info"
	}
}

// eventXML covers the part of an EvtRender result the source reads. The tag
// names carry no namespace because encoding/xml matches on the local name,
// which also matches the event schema's default namespace
// (http://schemas.microsoft.com/win/2004/08/events/event).
type eventXML struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"System>Provider"`
	Level       int `xml:"System>Level"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"System>TimeCreated"`
	RecordID uint64   `xml:"System>EventRecordID"`
	Data     []string `xml:"EventData>Data"`
}

// parseEventXML decodes the XML EvtRender produces for one event. A
// SystemTime it cannot date leaves the timestamp zero instead of failing the
// event: the message is still worth forwarding, and Collect stamps it.
func parseEventXML(data []byte) (EventRecord, error) {
	var event eventXML
	if err := xml.Unmarshal(data, &event); err != nil {
		return EventRecord{}, fmt.Errorf("logfwd: eventlog: parse event: %w", err)
	}

	// The service writes its record as one insertion string, but a publisher
	// may split an event over several, so all of them count. An event may
	// carry up to 256 KiB of them, so the join is capped the way FileSource
	// caps a log line rather than forwarded whole.
	message := strings.Join(event.Data, " ")
	if len(message) > MaxLineBytes {
		message = message[:MaxLineBytes] + truncatedSuffix
	}

	record := EventRecord{
		RecordID: event.RecordID,
		Level:    event.Level,
		Provider: event.Provider.Name,
		Message:  message,
	}
	if timestamp, err := time.Parse(time.RFC3339Nano, event.TimeCreated.SystemTime); err == nil {
		record.Timestamp = timestamp
	}
	return record, nil
}

// eventLogQuery builds the XPath the reader hands to EvtQuery: every event of
// provider since the last window on the first read, and every event of
// provider with a record id above afterRecordID on the reads after it. The
// record id resumes exactly where the previous read stopped, so an event is
// neither forwarded twice nor lost between two reads. provider is a fixed
// identifier (packaging.DefaultServiceName) and holds no quote to escape.
func eventLogQuery(provider string, afterRecordID uint64, window time.Duration) string {
	if afterRecordID == 0 {
		return fmt.Sprintf(
			"*[System[Provider[@Name='%s'] and TimeCreated[timediff(@SystemTime) <= %d]]]",
			provider, window.Milliseconds(),
		)
	}
	return fmt.Sprintf("*[System[Provider[@Name='%s'] and EventRecordID > %d]]", provider, afterRecordID)
}
