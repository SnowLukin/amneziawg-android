package loghistory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Directory:    t.TempDir(),
		ConnectionID: "connection-a",
		Policy: Policy{
			MaxSegmentBytes: 512,
			MaxSourceBytes:  2048,
			MaxSegments:     4,
			MaxPendingBytes: 512,
		},
	}
}

func readRecords(t *testing.T, directory string) []map[string]any {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "amneziawg.*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	var total int64
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 512 {
			t.Fatalf("segment exceeds budget: %d", len(data))
		}
		total += int64(len(data))
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatalf("invalid JSONL: %v", err)
			}
			records = append(records, record)
		}
	}
	if len(paths) > 4 || total > 2048 {
		t.Fatalf("ring exceeds budget: parts=%d bytes=%d", len(paths), total)
	}
	return records
}

func TestWriterRotatesJSONLAndKeepsUTF8Records(t *testing.T) {
	cfg := testConfig(t)
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if err := w.Write(Event{Timestamp: time.Unix(int64(i), 123456000), Level: "warning", Message: strings.Repeat("Ж", 90)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records := readRecords(t, cfg.Directory)
	if len(records) == 0 || records[len(records)-1]["source"] != "amneziawg" {
		t.Fatalf("latest record is missing: %#v", records)
	}
}

func TestManagerDrainsAndStopsAfterRevoke(t *testing.T) {
	cfg := testConfig(t)
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Configure(string(encoded)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		Log("debug", strings.Repeat("x", 160))
	}
	if err := Configure(""); err != nil {
		t.Fatal(err)
	}
	before := len(readRecords(t, cfg.Directory))
	Log("error", "after revoke")
	if after := len(readRecords(t, cfg.Directory)); after != before {
		t.Fatal("writer accepted a record after revoke")
	}
	state := StateJSON()
	if !strings.Contains(state, "\"status\":\"closed\"") {
		t.Fatalf("unexpected state: %s", state)
	}
}

func TestWorkerReportsDroppedEventsWhenPendingBudgetIsFull(t *testing.T) {
	cfg := testConfig(t)
	cfg.Policy.MaxPendingBytes = 1
	w, err := newWorker(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.Log("debug", "event cannot fit in the pending budget")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records := readRecords(t, cfg.Directory)
	if len(records) != 1 || records[0]["kind"] != "dropped" {
		t.Fatalf("missing dropped record: %#v", records)
	}
}

func TestWorkerKeepsFailedStateAfterRotationError(t *testing.T) {
	cfg := testConfig(t)
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Configure(string(encoded)); err != nil {
		t.Fatal(err)
	}
	Log("info", strings.Repeat("x", 240))
	if err := os.Mkdir(filepath.Join(cfg.Directory, "amneziawg.00000000000000000002.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	Log("info", strings.Repeat("x", 240))
	if err := Configure(""); err == nil {
		t.Fatal("worker rotation error was hidden")
	}
	var state State
	if err := json.Unmarshal([]byte(StateJSON()), &state); err != nil {
		t.Fatal(err)
	}
	if state.Status != "failed" || state.ErrorCode != "io_rotate" {
		t.Fatalf("failed worker was reported as %#v", state)
	}
	data, err := os.ReadFile(filepath.Join(cfg.Directory, "amneziawg.state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.Status != "failed" || state.ErrorCode != "io_rotate" {
		t.Fatalf("persisted state was overwritten as %#v", state)
	}
}

func TestManagerKeepsStateWriteFailureAfterDrain(t *testing.T) {
	cfg := testConfig(t)
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Configure(string(encoded)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(cfg.Directory, cfg.Directory+"-gone"); err != nil {
		t.Fatal(err)
	}
	if err := Configure(""); err == nil {
		t.Fatal("state write failure was hidden")
	}
	var state State
	if err := json.Unmarshal([]byte(StateJSON()), &state); err != nil {
		t.Fatal(err)
	}
	if state.Status != "failed" || state.ErrorCode != "io_state" {
		t.Fatalf("drain state write failure was reported as %#v", state)
	}
}
