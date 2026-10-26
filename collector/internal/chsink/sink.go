// Package chsink batches rows and inserts them into ClickHouse over its HTTP interface.
// If ClickHouse is down, rows are buffered up to MaxRows per table, then the oldest are dropped
// (and counted). Collection and live publishing never block on ClickHouse.
package chsink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	URL      string // http://127.0.0.1:8123
	Database string
	User     string
	Password string
	MaxRows  int
	Interval time.Duration
}

type Sink struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	tables map[string][][]byte

	Inserted, Dropped, Errors atomic.Uint64
	LastError                 atomic.Value // string
	LastOK                    atomic.Int64 // unix seconds
}

func New(cfg Config) *Sink {
	if cfg.MaxRows == 0 {
		cfg.MaxRows = 500_000
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Sink{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}, tables: map[string][][]byte{}}
}

// Add queues one row (any JSON-marshalable struct whose tags match the table columns).
func (s *Sink) Add(table string, row any) {
	b, err := json.Marshal(row)
	if err != nil {
		return
	}
	s.mu.Lock()
	q := append(s.tables[table], b)
	if over := len(q) - s.cfg.MaxRows; over > 0 {
		q = q[over:]
		s.Dropped.Add(uint64(over))
	}
	s.tables[table] = q
	s.mu.Unlock()
}

func (s *Sink) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			s.Flush(fctx)
			cancel()
			return
		case <-t.C:
			s.Flush(ctx)
		}
	}
}

func (s *Sink) Flush(ctx context.Context) {
	s.mu.Lock()
	batches := s.tables
	s.tables = map[string][][]byte{}
	s.mu.Unlock()
	for table, rows := range batches {
		if len(rows) == 0 {
			continue
		}
		if err := s.insert(ctx, table, rows); err != nil {
			s.Errors.Add(1)
			s.LastError.Store(err.Error())
			// Re-queue in front of anything that arrived meanwhile, still bounded.
			s.mu.Lock()
			q := append(rows, s.tables[table]...)
			if over := len(q) - s.cfg.MaxRows; over > 0 {
				q = q[over:]
				s.Dropped.Add(uint64(over))
			}
			s.tables[table] = q
			s.mu.Unlock()
			continue
		}
		s.Inserted.Add(uint64(len(rows)))
		s.LastOK.Store(time.Now().Unix())
	}
}

func (s *Sink) insert(ctx context.Context, table string, rows [][]byte) error {
	var body bytes.Buffer
	for _, r := range rows {
		body.Write(r)
		body.WriteByte('\n')
	}
	q := url.Values{}
	q.Set("query", fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", s.cfg.Database, table))
	q.Set("input_format_skip_unknown_fields", "1")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL+"/?"+q.Encode(), &body)
	if err != nil {
		return err
	}
	if s.cfg.User != "" {
		req.Header.Set("X-ClickHouse-User", s.cfg.User)
		req.Header.Set("X-ClickHouse-Key", s.cfg.Password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse %s: %d %s", table, resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

func (s *Sink) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, q := range s.tables {
		n += len(q)
	}
	return n
}
