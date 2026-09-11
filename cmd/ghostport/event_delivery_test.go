package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testAlert() ScanAlert {
	return ScanAlert{
		SchemaVersion: scanAlertSchemaVersion,
		Kind:          "scan_alert",
		Type:          ScanAlertVertical,
		SourceIP:      "10.0.0.1",
		Protocol:      "tcp",
		TargetIP:      "10.0.0.2",
		DistinctCount: 20,
		WindowSeconds: 30,
		Timestamp:     time.Unix(1000, 0).UTC(),
	}
}

func fastDeliveryConfig(endpoint string) eventDeliveryConfig {
	return eventDeliveryConfig{
		Endpoint:      endpoint,
		Timeout:       2 * time.Second,
		MaxRetries:    2,
		QueueSize:     10,
		ShutdownGrace: 2 * time.Second,
	}
}

// TestEventDeliverySendsAuthHeaderAndBody confirms the token is sent only
// as a Bearer Authorization header, and the delivered body matches the
// alert, using a local HTTPS test server.
func TestEventDeliverySendsAuthHeaderAndBody(t *testing.T) {
	var gotAuth string
	var gotAlert ScanAlert
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotAlert)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := newEventDelivery(fastDeliveryConfig(server.URL), "secret-token", server.Client())
	d.deliver(context.Background(), testAlert())

	if gotAuth != "Bearer secret-token" {
		t.Fatalf("Authorization header = %q, want %q", gotAuth, "Bearer secret-token")
	}
	if gotAlert.SourceIP != "10.0.0.1" || gotAlert.DistinctCount != 20 {
		t.Fatalf("delivered alert = %+v, want the test alert", gotAlert)
	}
}

// TestEventDeliveryRetriesOn5xxThenSucceeds confirms a transient server
// error is retried and a later success is accepted.
func TestEventDeliveryRetriesOn5xxThenSucceeds(t *testing.T) {
	var calls int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&calls, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := newEventDelivery(fastDeliveryConfig(server.URL), "t", server.Client())
	d.deliver(context.Background(), testAlert())

	if got := atomic.LoadInt64(&calls); got != 3 {
		t.Fatalf("handler called %d times, want 3 (2 failures + 1 success)", got)
	}
}

// TestEventDeliveryDoesNotRetryOn4xx confirms a client error (bad auth,
// bad request) is not retried, since retrying cannot fix it.
func TestEventDeliveryDoesNotRetryOn4xx(t *testing.T) {
	var calls int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	d := newEventDelivery(fastDeliveryConfig(server.URL), "t", server.Client())
	d.deliver(context.Background(), testAlert())

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("handler called %d times, want exactly 1 (no retries on 4xx)", got)
	}
}

// TestEventDeliveryGivesUpAfterMaxRetries confirms bounded retries: a
// permanently failing endpoint is called exactly MaxRetries+1 times, not
// forever.
func TestEventDeliveryGivesUpAfterMaxRetries(t *testing.T) {
	var calls int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := fastDeliveryConfig(server.URL)
	cfg.MaxRetries = 2
	d := newEventDelivery(cfg, "t", server.Client())
	d.deliver(context.Background(), testAlert())

	if got := atomic.LoadInt64(&calls); got != 3 {
		t.Fatalf("handler called %d times, want exactly 3 (MaxRetries=2 + first attempt)", got)
	}
}

// TestEventDeliveryRejectsUntrustedCertificate proves strict TLS
// validation: a client that does not trust the test server's certificate
// (i.e. an ordinary client, not server.Client()) must never reach the
// handler.
func TestEventDeliveryRejectsUntrustedCertificate(t *testing.T) {
	var calls int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := fastDeliveryConfig(server.URL)
	cfg.MaxRetries = 0
	untrusting := &http.Client{Timeout: 2 * time.Second} // does NOT trust server's self-signed cert
	d := newEventDelivery(cfg, "t", untrusting)
	d.deliver(context.Background(), testAlert())

	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("handler was called %d times with an untrusted certificate, want 0 (TLS validation must reject it)", got)
	}
}

// TestEventDeliveryEnqueueDropsWhenQueueFull confirms bounded buffering
// with explicit, counted drops instead of blocking the caller.
func TestEventDeliveryEnqueueDropsWhenQueueFull(t *testing.T) {
	cfg := fastDeliveryConfig("https://example.invalid")
	cfg.QueueSize = 1
	d := newEventDelivery(cfg, "t", &http.Client{})

	d.Enqueue(testAlert()) // fills the queue (capacity 1); nothing is draining it
	d.Enqueue(testAlert()) // must be dropped, not block

	if got := d.Dropped(); got != 1 {
		t.Fatalf("Dropped() = %d, want 1", got)
	}
}

// TestEventDeliveryDrainFlushesQueuedAlertsOnShutdown confirms alerts
// already queued when shutdown begins are still delivered (up to the grace
// period), rather than silently discarded.
func TestEventDeliveryDrainFlushesQueuedAlertsOnShutdown(t *testing.T) {
	var calls int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := newEventDelivery(fastDeliveryConfig(server.URL), "t", server.Client())
	for i := 0; i < 3; i++ {
		d.Enqueue(testAlert())
	}

	d.drain() // the same method Run() calls once its context is done

	if got := atomic.LoadInt64(&calls); got != 3 {
		t.Fatalf("handler called %d times during drain, want 3 (all queued alerts flushed)", got)
	}
}

// TestEventDeliveryRunStopsWhenContextCanceled confirms Run returns
// promptly (bounded by ShutdownGrace) once its context is canceled, rather
// than blocking forever, which matters for graceful process shutdown.
func TestEventDeliveryRunStopsWhenContextCanceled(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := fastDeliveryConfig(server.URL)
	cfg.ShutdownGrace = 200 * time.Millisecond
	d := newEventDelivery(cfg, "t", server.Client())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within a reasonable time after context cancellation")
	}
}

func TestRetryBackoffIsBoundedAndPositive(t *testing.T) {
	for attempt := 1; attempt <= 10; attempt++ {
		d := retryBackoff(attempt)
		if d <= 0 {
			t.Errorf("retryBackoff(%d) = %s, want > 0", attempt, d)
		}
		if d > 5*time.Second {
			t.Errorf("retryBackoff(%d) = %s, want <= 5s", attempt, d)
		}
	}
}
