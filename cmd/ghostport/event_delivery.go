package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync/atomic"
	"time"
)

// eventDeliveryConfig configures optional authenticated HTTPS delivery of
// scan alerts to an external endpoint. It is disabled by default and
// carries no default endpoint: no telemetry leaves the host unless an
// operator explicitly enables and configures it.
type eventDeliveryConfig struct {
	Enabled  bool
	Endpoint string // must be an https:// URL; enforced in parseConfig
	Timeout  time.Duration
	// MaxRetries is additional attempts after the first, for a retryable
	// failure (network/TLS error or a 5xx response). A 4xx response is
	// never retried, since retrying a rejected or unauthorized request
	// cannot succeed without operator intervention.
	MaxRetries int
	// QueueSize bounds how many alerts can be buffered waiting for
	// delivery. Once full, Enqueue drops the newest alert rather than
	// blocking the sensor's reporting loop or growing without bound.
	QueueSize int
	// ShutdownGrace bounds how long Run keeps attempting to drain queued
	// alerts after its context is canceled.
	ShutdownGrace time.Duration
}

func defaultEventDeliveryConfig() eventDeliveryConfig {
	return eventDeliveryConfig{
		Timeout:       5 * time.Second,
		MaxRetries:    3,
		QueueSize:     100,
		ShutdownGrace: 5 * time.Second,
	}
}

// eventDelivery delivers ScanAlerts to cfg.Endpoint over the given HTTP
// client. The caller is responsible for constructing a client with strict
// TLS validation (the zero-value http.Client, or one with only a Timeout
// set, already validates certificates normally; eventDelivery never
// disables that). authToken is held only in memory and sent solely as a
// Bearer Authorization header; it is never logged.
type eventDelivery struct {
	cfg       eventDeliveryConfig
	authToken string
	client    *http.Client

	queue   chan ScanAlert
	dropped uint64 // atomic
}

func newEventDelivery(cfg eventDeliveryConfig, authToken string, client *http.Client) *eventDelivery {
	return &eventDelivery{
		cfg:       cfg,
		authToken: authToken,
		client:    client,
		queue:     make(chan ScanAlert, cfg.QueueSize),
	}
}

// Enqueue never blocks. If the queue is full, the alert is dropped and
// counted rather than backing up the sensor's reporting loop.
func (d *eventDelivery) Enqueue(alert ScanAlert) {
	select {
	case d.queue <- alert:
	default:
		atomic.AddUint64(&d.dropped, 1)
		log.Printf("event delivery: queue full, dropped a %s alert for source %s", alert.Type, alert.SourceIP)
	}
}

// Dropped reports how many alerts have been dropped so far because the
// queue was full.
func (d *eventDelivery) Dropped() uint64 {
	return atomic.LoadUint64(&d.dropped)
}

// QueueDepth reports how many alerts are currently buffered awaiting
// delivery. Reading a channel's length is safe for concurrent use; this is
// a snapshot for the status event, not a value to synchronize on.
func (d *eventDelivery) QueueDepth() int {
	return len(d.queue)
}

// Run delivers queued alerts until ctx is done, then drains whatever is
// still queued for up to cfg.ShutdownGrace before returning. Run is meant
// to be driven from a single goroutine per eventDelivery instance.
func (d *eventDelivery) Run(ctx context.Context) {
	for {
		select {
		case alert := <-d.queue:
			d.deliver(ctx, alert)
		case <-ctx.Done():
			d.drain()
			return
		}
	}
}

func (d *eventDelivery) drain() {
	deadline := time.NewTimer(d.cfg.ShutdownGrace)
	defer deadline.Stop()
	for {
		select {
		case alert := <-d.queue:
			attemptCtx, cancel := context.WithTimeout(context.Background(), d.cfg.Timeout)
			d.deliver(attemptCtx, alert)
			cancel()
		case <-deadline.C:
			return
		default:
			return
		}
	}
}

func (d *eventDelivery) deliver(ctx context.Context, alert ScanAlert) {
	body, err := json.Marshal(alert)
	if err != nil {
		log.Printf("event delivery: encode alert: %v", err)
		return
	}

	var lastErr error
	for attempt := 0; attempt <= d.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(retryBackoff(attempt)):
			case <-ctx.Done():
				return
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.Endpoint, bytes.NewReader(body))
		if err != nil {
			log.Printf("event delivery: build request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+d.authToken)

		resp, err := d.client.Do(req)
		if err != nil {
			// Network/TLS errors (including certificate validation
			// failures) are retryable; the error string itself never
			// contains the auth token, which is sent only as a header.
			lastErr = err
			continue
		}
		resp.Body.Close()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return
		case resp.StatusCode >= 400 && resp.StatusCode < 500:
			log.Printf("event delivery: endpoint rejected alert with status %d, not retrying", resp.StatusCode)
			return
		default:
			lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
	}
	if lastErr != nil {
		log.Printf("event delivery: giving up after %d attempts: %v", d.cfg.MaxRetries+1, lastErr)
	}
}

// retryBackoff returns an exponential backoff with jitter for the given
// attempt number (1-indexed: the first retry, not the first attempt),
// capped at 5 seconds.
func retryBackoff(attempt int) time.Duration {
	const (
		base    = 200 * time.Millisecond
		maxWait = 5 * time.Second
	)
	d := base << uint(attempt-1) // #nosec G115 -- attempt is a small, internally bounded loop counter
	if d > maxWait || d <= 0 {
		d = maxWait
	}
	jitter := time.Duration(rand.Int63n(int64(d)/2 + 1)) //nolint:gosec // jitter timing, not a security decision
	return d/2 + jitter
}
