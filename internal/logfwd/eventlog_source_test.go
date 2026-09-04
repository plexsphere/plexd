package logfwd

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// eventFixture is one event in the shape EvtRender returns it.
const eventFixture = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>` +
	`<System><Provider Name='plexd'/><EventID Qualifiers='0'>1</EventID><Version>0</Version>` +
	`<Level>3</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords>` +
	`<TimeCreated SystemTime='2026-09-04T10:00:00.1234567Z'/><EventRecordID>4711</EventRecordID>` +
	`<Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>Application</Channel>` +
	`<Computer>host1</Computer><Security/></System>` +
	`<EventData><Data>level=WARN msg="tunnel down"</Data></EventData></Event>`

type mockEventLogReader struct {
	records []EventRecord
	err     error
}

func (m *mockEventLogReader) ReadEvents(_ context.Context) ([]EventRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.records, nil
}

func TestEventLogSource_Collect_MapsFields(t *testing.T) {
	timestamp := time.Date(2026, 9, 4, 10, 0, 0, 123456700, time.UTC)
	const message = `level=WARN msg="tunnel down"`
	reader := &mockEventLogReader{
		records: []EventRecord{
			{RecordID: 4711, Timestamp: timestamp, Level: 3, Provider: "plexd", Message: message},
		},
	}
	src := NewEventLogSource(reader, "host1")

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Source != "eventlog" {
		t.Errorf("Source = %q, want %q", entry.Source, "eventlog")
	}
	if entry.Unit != "plexd" {
		t.Errorf("Unit = %q, want %q", entry.Unit, "plexd")
	}
	if entry.Message != message {
		t.Errorf("Message = %q, want %q", entry.Message, message)
	}
	if entry.Severity != "warning" {
		t.Errorf("Severity = %q, want %q", entry.Severity, "warning")
	}
	if entry.Hostname != "host1" {
		t.Errorf("Hostname = %q, want %q", entry.Hostname, "host1")
	}
	if !entry.Timestamp.Equal(timestamp) {
		t.Errorf("Timestamp = %v, want %v", entry.Timestamp, timestamp)
	}
}

func TestEventLogSource_Collect_MapsLevelToSeverity(t *testing.T) {
	timestamp := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		level int
		want  string
	}{
		{"unset", 0, "info"},
		{"critical", 1, "crit"},
		{"error", 2, "err"},
		{"warning", 3, "warning"},
		{"information", 4, "info"},
		{"verbose", 5, "debug"},
		{"undefined", 6, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &mockEventLogReader{
				records: []EventRecord{
					{RecordID: 1, Timestamp: timestamp, Level: tt.level, Provider: "plexd", Message: "msg"},
				},
			}
			src := NewEventLogSource(reader, "host1")

			entries, err := src.Collect(context.Background())
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("len(entries) = %d, want 1", len(entries))
			}
			if entries[0].Severity != tt.want {
				t.Errorf("level %d: Severity = %q, want %q", tt.level, entries[0].Severity, tt.want)
			}
		})
	}
}

func TestEventLogSource_Collect_ZeroTimestampUsesNow(t *testing.T) {
	reader := &mockEventLogReader{
		records: []EventRecord{
			{RecordID: 1, Level: 4, Provider: "plexd", Message: "msg"},
		},
	}
	src := NewEventLogSource(reader, "host1")

	before := time.Now()
	entries, err := src.Collect(context.Background())
	after := time.Now()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}

	got := entries[0].Timestamp
	if got.Before(before) || got.After(after) {
		t.Errorf("Timestamp = %v, want it inside [%v, %v]", got, before, after)
	}
}

func TestEventLogSource_Collect_HandlesReaderError(t *testing.T) {
	sentinel := errors.New("boom")
	src := NewEventLogSource(&mockEventLogReader{err: sentinel}, "host1")

	entries, err := src.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error")
	}
	if entries != nil {
		t.Errorf("entries = %v, want nil", entries)
	}
	if !strings.HasPrefix(err.Error(), "logfwd: eventlog:") {
		t.Errorf("error = %q, want it to start with %q", err.Error(), "logfwd: eventlog:")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want it to wrap %v", err, sentinel)
	}
}

func TestEventLogSource_Collect_ReturnsEmptyOnNoEvents(t *testing.T) {
	tests := []struct {
		name    string
		records []EventRecord
	}{
		{"empty slice", []EventRecord{}},
		{"nil slice", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := NewEventLogSource(&mockEventLogReader{records: tt.records}, "host1")

			entries, err := src.Collect(context.Background())
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}
			if entries != nil {
				t.Errorf("entries = %v, want nil", entries)
			}
		})
	}
}

func TestParseEventXML(t *testing.T) {
	record, err := parseEventXML([]byte(eventFixture))
	if err != nil {
		t.Fatalf("parseEventXML() error = %v", err)
	}

	if record.Provider != "plexd" {
		t.Errorf("Provider = %q, want %q", record.Provider, "plexd")
	}
	if record.Level != 3 {
		t.Errorf("Level = %d, want 3", record.Level)
	}
	if record.RecordID != 4711 {
		t.Errorf("RecordID = %d, want 4711", record.RecordID)
	}
	want := time.Date(2026, 9, 4, 10, 0, 0, 123456700, time.UTC)
	if !record.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", record.Timestamp, want)
	}
	const wantMessage = `level=WARN msg="tunnel down"`
	if record.Message != wantMessage {
		t.Errorf("Message = %q, want %q", record.Message, wantMessage)
	}
}

func TestParseEventXML_TwoDataJoined(t *testing.T) {
	const doc = `<Event><System><Provider Name='plexd'/><Level>4</Level>` +
		`<EventRecordID>1</EventRecordID></System>` +
		`<EventData><Data>a</Data><Data>b</Data></EventData></Event>`

	record, err := parseEventXML([]byte(doc))
	if err != nil {
		t.Fatalf("parseEventXML() error = %v", err)
	}
	if record.Message != "a b" {
		t.Errorf("Message = %q, want %q", record.Message, "a b")
	}
}

func TestParseEventXML_NoDataIsEmptyMessage(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{
			name: "no EventData",
			doc: `<Event><System><Provider Name='plexd'/><Level>4</Level>` +
				`<EventRecordID>7</EventRecordID></System></Event>`,
		},
		{
			name: "empty EventData",
			doc: `<Event><System><Provider Name='plexd'/><Level>4</Level>` +
				`<EventRecordID>7</EventRecordID></System><EventData></EventData></Event>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := parseEventXML([]byte(tt.doc))
			if err != nil {
				t.Fatalf("parseEventXML() error = %v", err)
			}
			if record.Message != "" {
				t.Errorf("Message = %q, want empty", record.Message)
			}
			if record.RecordID != 7 {
				t.Errorf("RecordID = %d, want 7", record.RecordID)
			}
		})
	}
}

func TestParseEventXML_BadSystemTimeIsZero(t *testing.T) {
	const doc = `<Event><System><Provider Name='plexd'/><Level>2</Level>` +
		`<TimeCreated SystemTime='yesterday'/><EventRecordID>4711</EventRecordID></System>` +
		`<EventData><Data>msg</Data></EventData></Event>`

	record, err := parseEventXML([]byte(doc))
	if err != nil {
		t.Fatalf("parseEventXML() error = %v", err)
	}
	if !record.Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want the zero time", record.Timestamp)
	}
	if record.Provider != "plexd" {
		t.Errorf("Provider = %q, want %q", record.Provider, "plexd")
	}
	if record.Level != 2 {
		t.Errorf("Level = %d, want 2", record.Level)
	}
	if record.RecordID != 4711 {
		t.Errorf("RecordID = %d, want 4711", record.RecordID)
	}
	if record.Message != "msg" {
		t.Errorf("Message = %q, want %q", record.Message, "msg")
	}
}

func TestParseEventXML_Malformed(t *testing.T) {
	record, err := parseEventXML([]byte(`<Event><System><Provider Name='plexd'/>`))
	if err == nil {
		t.Fatal("parseEventXML() error = nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "logfwd: eventlog: parse event:") {
		t.Errorf("error = %q, want it to start with %q", err.Error(), "logfwd: eventlog: parse event:")
	}
	if record != (EventRecord{}) {
		t.Errorf("record = %+v, want the zero record", record)
	}
}

func TestParseEventXML_Empty(t *testing.T) {
	_, err := parseEventXML([]byte{})
	if err == nil {
		t.Fatal("parseEventXML() error = nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "logfwd: eventlog: parse event:") {
		t.Errorf("error = %q, want it to start with %q", err.Error(), "logfwd: eventlog: parse event:")
	}
	if !errors.Is(err, io.EOF) {
		t.Errorf("error = %v, want it to wrap %v", err, io.EOF)
	}
}

func TestEventLogQuery(t *testing.T) {
	tests := []struct {
		name          string
		afterRecordID uint64
		want          string
	}{
		{
			name:          "first read takes the window",
			afterRecordID: 0,
			want:          `*[System[Provider[@Name='plexd'] and TimeCreated[timediff(@SystemTime) <= 60000]]]`,
		},
		{
			name:          "later read resumes above the record id",
			afterRecordID: 123,
			want:          `*[System[Provider[@Name='plexd'] and EventRecordID > 123]]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eventLogQuery("plexd", tt.afterRecordID, 60*time.Second)
			if got != tt.want {
				t.Errorf("eventLogQuery() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestEventLogSource_Collect_DropsOwnRecords pins the loop the Windows pair
// would otherwise close: the service logs to the same Application channel the
// source reads, so the forwarder's own warnings must not come back as input.
func TestEventLogSource_Collect_DropsOwnRecords(t *testing.T) {
	reader := &mockEventLogReader{
		records: []EventRecord{
			{RecordID: 1, Timestamp: time.Now(), Level: 3, Provider: "plexd",
				Message: `level=WARN msg="log report failed" component=logfwd error="dial tcp: refused"`},
			{RecordID: 2, Timestamp: time.Now(), Level: 4, Provider: "plexd",
				Message: `level=INFO msg="peer added" component=tunnel`},
		},
	}
	src := NewEventLogSource(reader, "host1")

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if strings.Contains(entries[0].Message, "component=logfwd") {
		t.Errorf("entries[0].Message = %q, want the forwarder's own record dropped", entries[0].Message)
	}
}

// TestEventLogSource_Collect_OnlyOwnRecords covers the steady state of a
// control-plane outage, where every event in the channel is one the forwarder
// wrote: the collection has to yield nothing at all.
func TestEventLogSource_Collect_OnlyOwnRecords(t *testing.T) {
	reader := &mockEventLogReader{
		records: []EventRecord{
			{RecordID: 1, Timestamp: time.Now(), Level: 3, Provider: "plexd",
				Message: `level=WARN msg="buffer overflow, dropping oldest entries" component=logfwd dropped=64`},
		},
	}
	src := NewEventLogSource(reader, "host1")

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if entries != nil {
		t.Errorf("entries = %v, want nil", entries)
	}
}

// TestParseEventXML_TruncatesLongMessage bounds what a publisher can put into
// one entry. The Application channel is writable by every interactive user, so
// the insertion strings are not the service's to size.
func TestParseEventXML_TruncatesLongMessage(t *testing.T) {
	long := strings.Repeat("x", MaxLineBytes+100)
	xml := `<Event><System><Provider Name='plexd'/><Level>4</Level>` +
		`<TimeCreated SystemTime='2026-09-04T10:00:00.0000000Z'/><EventRecordID>1</EventRecordID>` +
		`</System><EventData><Data>` + long + `</Data></EventData></Event>`

	record, err := parseEventXML([]byte(xml))
	if err != nil {
		t.Fatalf("parseEventXML() error = %v", err)
	}
	if want := MaxLineBytes + len(truncatedSuffix); len(record.Message) != want {
		t.Errorf("len(Message) = %d, want %d", len(record.Message), want)
	}
	if !strings.HasSuffix(record.Message, truncatedSuffix) {
		t.Errorf("Message does not end in %q", truncatedSuffix)
	}
}
