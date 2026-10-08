package loghistory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const stem = "amneziawg"

type Policy struct {
	MaxSegmentBytes int64 `json:"maxSegmentBytes"`
	MaxSourceBytes  int64 `json:"maxSourceBytes"`
	MaxSegments     int   `json:"maxSegments"`
	MaxPendingBytes int64 `json:"maxPendingBytes"`
}

func DefaultPolicy() Policy {
	return Policy{MaxSegmentBytes: 2 * 1024 * 1024, MaxSourceBytes: 8 * 1024 * 1024, MaxSegments: 4, MaxPendingBytes: 512 * 1024}
}

func (p Policy) validate() error {
	if p.MaxSegmentBytes < 512 || p.MaxSourceBytes < p.MaxSegmentBytes || p.MaxSegments < 1 || int64(p.MaxSegments) > p.MaxSourceBytes/p.MaxSegmentBytes || p.MaxPendingBytes < 1 {
		return errors.New("invalid_log_history_policy")
	}
	return nil
}

type Config struct {
	Directory    string `json:"directory"`
	ConnectionID string `json:"connectionId"`
	Policy       Policy `json:"policy"`
}

type Event struct {
	Timestamp time.Time
	Level     string
	Message   string
	Kind      string
}

type State struct {
	Version      int     `json:"v"`
	Status       string  `json:"status"`
	ConnectionID *string `json:"connectionId,omitempty"`
	ErrorCode    string  `json:"errorCode,omitempty"`
}

type envelope struct {
	Version      int       `json:"v"`
	Timestamp    time.Time `json:"timestamp"`
	Source       string    `json:"source"`
	Level        string    `json:"level"`
	ConnectionID *string   `json:"connectionId"`
	Kind         string    `json:"kind,omitempty"`
	Message      string    `json:"message"`
}

type part struct {
	path string
	size int64
	seq  uint64
}

type Writer struct {
	mu       sync.Mutex
	config   Config
	state    State
	parts    []part
	file     *os.File
	sequence uint64
	closed   bool
}

func normalize(config Config) (Config, error) {
	if config.Policy == (Policy{}) {
		config.Policy = DefaultPolicy()
	}
	if config.Policy.MaxPendingBytes == 0 {
		config.Policy.MaxPendingBytes = DefaultPolicy().MaxPendingBytes
	}
	if err := config.Policy.validate(); err != nil || !filepath.IsAbs(config.Directory) || len(config.ConnectionID) > 512 {
		return Config{}, errors.New("invalid_log_history_config")
	}
	return config, nil
}

func connectionID(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func New(config Config) (*Writer, error) {
	config, err := normalize(config)
	if err != nil {
		return nil, err
	}
	w := &Writer{config: config, state: State{Version: 1, Status: "active", ConnectionID: connectionID(config.ConnectionID)}}
	if err := os.MkdirAll(config.Directory, 0700); err != nil {
		return nil, w.fail("io_open", err)
	}
	if err := w.load(); err != nil {
		return nil, w.fail("io_read", err)
	}
	if len(w.parts) > 0 {
		last := w.parts[len(w.parts)-1]
		if last.size < config.Policy.MaxSegmentBytes && complete(last.path, last.size) {
			w.file, err = os.OpenFile(last.path, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				return nil, w.fail("io_open", err)
			}
		}
	}
	if w.file == nil {
		if err := w.openNext(); err != nil {
			return nil, w.fail("io_open", err)
		}
	}
	if err := w.trim(0); err != nil {
		return nil, w.fail("io_rotate", err)
	}
	if err := w.saveState(); err != nil {
		return nil, w.fail("io_state", err)
	}
	return w, nil
}

func complete(path string, size int64) bool {
	if size == 0 {
		return true
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var last [1]byte
	_, err = f.ReadAt(last[:], size-1)
	return err == nil && last[0] == '\n'
}

func (w *Writer) load() error {
	entries, err := os.ReadDir(w.config.Directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), stem+".") || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		number := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), stem+"."), ".jsonl")
		if len(number) != 20 {
			continue
		}
		seq, err := strconv.ParseUint(number, 10, 64)
		if err != nil || seq == 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		w.parts = append(w.parts, part{path: filepath.Join(w.config.Directory, entry.Name()), size: info.Size(), seq: seq})
		if seq > w.sequence {
			w.sequence = seq
		}
	}
	sort.Slice(w.parts, func(i, j int) bool { return w.parts[i].seq < w.parts[j].seq })
	return nil
}

func (w *Writer) openNext() error {
	if w.sequence == ^uint64(0) {
		return errors.New("log_history_sequence_exhausted")
	}
	w.sequence++
	path := filepath.Join(w.config.Directory, fmt.Sprintf("%s.%020d.jsonl", stem, w.sequence))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	w.file = f
	w.parts = append(w.parts, part{path: path, seq: w.sequence})
	return nil
}

func encode(config Config, event Event) ([]byte, error) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if int64(len(event.Message)) > min(config.Policy.MaxSegmentBytes, config.Policy.MaxPendingBytes) {
		event.Message = "<message omitted: exceeds log event budget>"
	}
	record := envelope{Version: 1, Timestamp: event.Timestamp.UTC().Truncate(time.Microsecond), Source: stem, Level: event.Level, ConnectionID: connectionID(config.ConnectionID), Kind: event.Kind, Message: event.Message}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if int64(len(data)+1) > config.Policy.MaxSegmentBytes {
		record.Message = "<message omitted: exceeds log segment budget>"
		data, err = json.Marshal(record)
		if err != nil || int64(len(data)+1) > config.Policy.MaxSegmentBytes {
			return nil, errors.New("log_event_metadata_exceeds_budget")
		}
	}
	return append(data, '\n'), nil
}

func (w *Writer) Write(event Event) error {
	data, err := encode(w.config, event)
	if err != nil {
		return err
	}
	return w.writeRecord(data)
}

func (w *Writer) writeRecord(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.state.Status == "failed" {
		return errors.New("log_history_closed")
	}
	current := &w.parts[len(w.parts)-1]
	if current.size > 0 && current.size+int64(len(data)) > w.config.Policy.MaxSegmentBytes {
		if err := w.file.Close(); err != nil {
			return w.fail("io_close", err)
		}
		w.file = nil
		if err := w.trim(int64(len(data))); err != nil {
			return w.fail("io_rotate", err)
		}
		if err := w.openNext(); err != nil {
			return w.fail("io_rotate", err)
		}
	}
	if err := w.trim(int64(len(data))); err != nil {
		return w.fail("io_rotate", err)
	}
	n, err := w.file.Write(data)
	w.parts[len(w.parts)-1].size += int64(n)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return w.fail("io_write", err)
	}
	return nil
}

func (w *Writer) trim(incoming int64) error {
	var total int64
	for _, part := range w.parts {
		total += part.size
	}
	for len(w.parts) > w.config.Policy.MaxSegments || total+incoming > w.config.Policy.MaxSourceBytes {
		if len(w.parts) <= 1 {
			return errors.New("log_history_budget_exhausted")
		}
		oldest := w.parts[0]
		if err := os.Remove(oldest.path); err != nil {
			return err
		}
		total -= oldest.size
		w.parts = w.parts[1:]
	}
	return nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			return w.fail("io_flush", err)
		}
		if err := w.file.Close(); err != nil {
			return w.fail("io_close", err)
		}
		w.file = nil
	}
	if w.state.Status == "failed" {
		if err := w.saveState(); err != nil {
			return w.fail("io_state", err)
		}
		return errors.New(w.state.ErrorCode)
	}
	w.state.Status = "closed"
	if err := w.saveState(); err != nil {
		return w.fail("io_state", err)
	}
	return nil
}

func (w *Writer) State() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

func (w *Writer) fail(code string, cause error) error {
	w.state.Status = "failed"
	w.state.ErrorCode = code
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	_ = w.saveState()
	return fmt.Errorf("%s: %w", code, cause)
}

func (w *Writer) saveState() error {
	data, err := json.Marshal(w.state)
	if err != nil || len(data) > 4096 {
		return errors.New("log_history_state_write")
	}
	temp := filepath.Join(w.config.Directory, "."+stem+".state.tmp")
	state := filepath.Join(w.config.Directory, stem+".state.json")
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	return os.Rename(temp, state)
}

type worker struct {
	config  Config
	writer  *Writer
	mu      sync.Mutex
	queue   [][]byte
	pending int64
	dropped uint64
	closing bool
	wake    chan struct{}
	done    chan struct{}
	err     error
}

func newWorker(config Config) (*worker, error) {
	writer, err := New(config)
	if err != nil {
		return nil, err
	}
	w := &worker{config: config, writer: writer, wake: make(chan struct{}, 1), done: make(chan struct{})}
	go w.run()
	return w, nil
}

func (w *worker) Log(level, message string) {
	data, err := encode(w.config, Event{Timestamp: time.Now(), Level: level, Message: message})
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil || w.closing {
		return
	}
	if w.dropped > 0 {
		marker, _ := encode(w.config, Event{Timestamp: time.Now(), Level: "warning", Kind: "dropped", Message: fmt.Sprintf("%d log events dropped: pending byte limit", w.dropped)})
		if int64(len(marker)) <= w.config.Policy.MaxPendingBytes-w.pending {
			w.queue = append(w.queue, marker)
			w.pending += int64(len(marker))
			w.dropped = 0
		}
	}
	if int64(len(data)) > w.config.Policy.MaxPendingBytes-w.pending {
		if w.dropped < ^uint64(0) {
			w.dropped++
		}
	} else {
		w.queue = append(w.queue, data)
		w.pending += int64(len(data))
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *worker) run() {
	defer close(w.done)
	for {
		<-w.wake
		for {
			w.mu.Lock()
			var marker []byte
			var markerErr error
			if len(w.queue) == 0 && w.dropped > 0 {
				marker, markerErr = encode(w.config, Event{Timestamp: time.Now(), Level: "warning", Kind: "dropped", Message: fmt.Sprintf("%d log events dropped: pending byte limit", w.dropped)})
				w.dropped = 0
			}
			if len(w.queue) == 0 {
				closing := w.closing
				w.mu.Unlock()
				if markerErr != nil {
					w.writer.mu.Lock()
					w.err = w.writer.fail("record_too_large", markerErr)
					w.writer.mu.Unlock()
					return
				}
				if marker != nil {
					if err := w.writer.writeRecord(marker); err != nil {
						w.err = err
						_ = w.writer.Close()
						return
					}
					continue
				}
				if closing {
					w.err = w.writer.Close()
					return
				}
				break
			}
			data := w.queue[0]
			w.queue = w.queue[1:]
			w.mu.Unlock()
			err := w.writer.writeRecord(data)
			w.mu.Lock()
			w.pending -= int64(len(data))
			w.mu.Unlock()
			if err != nil {
				w.err = err
				_ = w.writer.Close()
				return
			}
		}
	}
}

func (w *worker) Close() error {
	w.mu.Lock()
	w.closing = true
	select {
	case w.wake <- struct{}{}:
	default:
	}
	w.mu.Unlock()
	<-w.done
	return w.err
}

type manager struct {
	mu     sync.Mutex
	active *worker
	state  State
}

var global manager

func Configure(raw string) error {
	raw = strings.TrimSpace(raw)
	global.mu.Lock()
	old := global.active
	global.active = nil
	global.mu.Unlock()
	if old != nil {
		closeErr := old.Close()
		global.mu.Lock()
		global.state = old.writer.State()
		global.mu.Unlock()
		if closeErr != nil {
			return closeErr
		}
	}
	if raw == "" || raw == "null" {
		return nil
	}
	var config Config
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return errors.New("invalid_log_history_config")
	}
	active, err := newWorker(config)
	if err != nil {
		global.mu.Lock()
		global.state = State{Version: 1, Status: "failed", ErrorCode: "io_open"}
		global.mu.Unlock()
		return err
	}
	global.mu.Lock()
	global.active = active
	global.state = active.writer.State()
	global.mu.Unlock()
	return nil
}

func Log(level, message string) {
	global.mu.Lock()
	active := global.active
	global.mu.Unlock()
	if active != nil {
		active.Log(level, message)
	}
}

func StateJSON() string {
	global.mu.Lock()
	state := global.state
	if global.active != nil {
		state = global.active.writer.State()
	}
	global.mu.Unlock()
	if state.Version == 0 {
		state = State{Version: 1, Status: "closed"}
	}
	data, err := json.Marshal(state)
	if err != nil {
		return `{"v":1,"status":"failed","errorCode":"state_encode"}`
	}
	return string(data)
}
