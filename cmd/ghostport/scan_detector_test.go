package main

import (
	"encoding/json"
	"testing"
	"time"
)

func testConfig() scanDetectorConfig {
	return scanDetectorConfig{
		Window:                  10 * time.Second,
		VerticalPortThreshold:   5,
		HorizontalHostThreshold: 5,
		Cooldown:                20 * time.Second,
		MaxTrackedSources:       8,
	}
}

func tcpRecord(src, dst string, port uint16, packets uint64) trafficRecord {
	return trafficRecord{SourceIP: src, DestinationIP: dst, Protocol: "tcp", DestinationPort: port, Packets: packets}
}

// TestScanDetectorBenignBurstNoAlert: a source touching a handful of ports
// on one destination, well under the threshold, must not alert.
func TestScanDetectorBenignBurstNoAlert(t *testing.T) {
	d := newScanDetector(testConfig())
	now := time.Unix(1000, 0)

	var records []trafficRecord
	for port := uint16(1); port <= 3; port++ {
		records = append(records, tcpRecord("10.0.0.1", "10.0.0.2", port, 1))
	}
	alerts := d.Observe(now, records)
	if len(alerts) != 0 {
		t.Fatalf("got %d alerts for a 3-port benign burst under threshold 5, want 0: %+v", len(alerts), alerts)
	}
}

// TestScanDetectorVerticalScan: a source crossing the vertical threshold on
// one destination must produce exactly one vertical alert with the right
// fields.
func TestScanDetectorVerticalScan(t *testing.T) {
	d := newScanDetector(testConfig())
	now := time.Unix(1000, 0)

	var records []trafficRecord
	for port := uint16(1); port <= 5; port++ {
		records = append(records, tcpRecord("10.0.0.1", "10.0.0.2", port, 1))
	}
	alerts := d.Observe(now, records)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.Type != ScanAlertVertical || a.SourceIP != "10.0.0.1" || a.TargetIP != "10.0.0.2" || a.DistinctCount != 5 || a.Protocol != "tcp" {
		t.Fatalf("unexpected alert: %+v", a)
	}
	if a.SchemaVersion != scanAlertSchemaVersion || a.Kind != "scan_alert" {
		t.Fatalf("unexpected alert envelope: %+v", a)
	}
}

// TestScanDetectorHorizontalScan: a source crossing the horizontal
// threshold on one port across many destinations must produce exactly one
// horizontal alert.
func TestScanDetectorHorizontalScan(t *testing.T) {
	d := newScanDetector(testConfig())
	now := time.Unix(1000, 0)

	var records []trafficRecord
	for i := 0; i < 5; i++ {
		dst := "10.0.0." + string(rune('1'+i))
		records = append(records, tcpRecord("10.0.0.1", dst, 22, 1))
	}
	alerts := d.Observe(now, records)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.Type != ScanAlertHorizontal || a.SourceIP != "10.0.0.1" || a.TargetPort != 22 || a.DistinctCount != 5 {
		t.Fatalf("unexpected alert: %+v", a)
	}
}

// TestScanDetectorDuplicateTrafficDoesNotInflateCount replays the exact
// same cumulative snapshot (no new packets) repeatedly; it must never
// alert, because nothing new is happening.
func TestScanDetectorDuplicateTrafficDoesNotInflateCount(t *testing.T) {
	d := newScanDetector(testConfig())
	now := time.Unix(1000, 0)

	var records []trafficRecord
	for port := uint16(1); port <= 3; port++ {
		records = append(records, tcpRecord("10.0.0.1", "10.0.0.2", port, 1))
	}
	for i := 0; i < 10; i++ {
		now = now.Add(time.Second)
		alerts := d.Observe(now, records) // identical, unchanged counts each time
		if len(alerts) != 0 {
			t.Fatalf("iteration %d: got %d alerts for replayed duplicate traffic, want 0", i, len(alerts))
		}
	}
}

// TestScanDetectorExpiredWindow: touches spread out slower than the window
// expire before enough of them accumulate, so a slow, spread-out probe
// pattern below the window's pace does not alert.
func TestScanDetectorExpiredWindow(t *testing.T) {
	cfg := testConfig() // Window: 10s, VerticalPortThreshold: 5
	d := newScanDetector(cfg)
	now := time.Unix(1000, 0)

	// One new port every 6 seconds: by the time the 5th arrives, the 1st
	// (30s ago... actually 24s ago) has long since aged out of the 10s
	// window, so at most 2 ports are ever in-window simultaneously.
	for i, port := 0, uint16(1); i < 5; i, port = i+1, port+1 {
		now = now.Add(6 * time.Second)
		alerts := d.Observe(now, []trafficRecord{tcpRecord("10.0.0.1", "10.0.0.2", port, 1)})
		if len(alerts) != 0 {
			t.Fatalf("touch %d: got %d alerts for a slow probe spread past the window, want 0", i, len(alerts))
		}
	}
}

// TestScanDetectorWithinWindowAccumulates is the counterpart to the expired
// window test: touches spaced closer together than the window all count.
func TestScanDetectorWithinWindowAccumulates(t *testing.T) {
	cfg := testConfig() // Window: 10s, VerticalPortThreshold: 5
	d := newScanDetector(cfg)
	now := time.Unix(1000, 0)

	var lastAlerts []ScanAlert
	for i, port := 0, uint16(1); i < 5; i, port = i+1, port+1 {
		now = now.Add(time.Second) // all 5 touches land within the 10s window
		lastAlerts = d.Observe(now, []trafficRecord{tcpRecord("10.0.0.1", "10.0.0.2", port, 1)})
	}
	if len(lastAlerts) != 1 || lastAlerts[0].Type != ScanAlertVertical {
		t.Fatalf("got %+v after 5 touches within the window, want exactly one vertical alert", lastAlerts)
	}
}

// TestScanDetectorCooldownSuppressesRepeatAlerts confirms a sustained scan
// produces one alert per cooldown period, not one alert per touch. Window
// is kept generous relative to cooldown so earlier touches are still valid
// when the cooldown expires, isolating cooldown behavior from window
// expiry (covered separately in TestScanDetectorExpiredWindow).
func TestScanDetectorCooldownSuppressesRepeatAlerts(t *testing.T) {
	cfg := scanDetectorConfig{
		Window:                  30 * time.Second,
		VerticalPortThreshold:   5,
		HorizontalHostThreshold: 5,
		Cooldown:                5 * time.Second,
		MaxTrackedSources:       8,
	}
	d := newScanDetector(cfg)
	now := time.Unix(1000, 0)

	var records []trafficRecord
	for port := uint16(1); port <= 5; port++ {
		records = append(records, tcpRecord("10.0.0.1", "10.0.0.2", port, 1))
	}
	if alerts := d.Observe(now, records); len(alerts) != 1 {
		t.Fatalf("first crossing: got %d alerts, want 1", len(alerts))
	}

	// One more new port, 2 seconds later: still within the 5s cooldown.
	now = now.Add(2 * time.Second)
	records = append(records, tcpRecord("10.0.0.1", "10.0.0.2", 6, 1))
	if alerts := d.Observe(now, records); len(alerts) != 0 {
		t.Fatalf("within cooldown: got %d alerts, want 0: %+v", len(alerts), alerts)
	}

	// Past the cooldown (8s since the first alert), with yet another new
	// port: should alert again, since all earlier ports are still within
	// the 30s window.
	now = now.Add(6 * time.Second)
	records = append(records, tcpRecord("10.0.0.1", "10.0.0.2", 7, 1))
	if alerts := d.Observe(now, records); len(alerts) != 1 {
		t.Fatalf("after cooldown: got %d alerts, want 1: %+v", len(alerts), alerts)
	}
}

// TestScanDetectorMapReset simulates the BPF map's LRU eviction resetting a
// flow's cumulative counter back to 1: the detector must treat this as a
// fresh touch instead of computing a negative delta or crashing.
func TestScanDetectorMapReset(t *testing.T) {
	d := newScanDetector(testConfig())
	now := time.Unix(1000, 0)

	if alerts := d.Observe(now, []trafficRecord{tcpRecord("10.0.0.1", "10.0.0.2", 80, 50)}); len(alerts) != 0 {
		t.Fatalf("initial touch: got %d alerts, want 0", len(alerts))
	}

	// Same flow reappears with a lower count than before (eviction reset).
	now = now.Add(time.Second)
	var records []trafficRecord
	records = append(records, tcpRecord("10.0.0.1", "10.0.0.2", 80, 1))
	for port := uint16(81); port <= 84; port++ {
		records = append(records, tcpRecord("10.0.0.1", "10.0.0.2", port, 1))
	}
	alerts := d.Observe(now, records)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts after reset + 4 new ports (5 distinct total), want 1: %+v", len(alerts), alerts)
	}
	if alerts[0].DistinctCount != 5 {
		t.Fatalf("DistinctCount = %d, want 5 (the reset flow must still count as touched)", alerts[0].DistinctCount)
	}
}

// TestScanDetectorMaxTrackedSourcesBoundsMemory confirms the detector never
// tracks more than MaxTrackedSources distinct source IPs, evicting the
// least-recently-active one instead of growing without bound.
func TestScanDetectorMaxTrackedSourcesBoundsMemory(t *testing.T) {
	cfg := testConfig() // MaxTrackedSources: 8
	d := newScanDetector(cfg)
	now := time.Unix(1000, 0)

	for i := 0; i < 20; i++ {
		now = now.Add(time.Second)
		src := "10.0.1." + string(rune('a'+i)) // 20 distinct, fake-but-unique source strings
		d.Observe(now, []trafficRecord{tcpRecord(src, "10.0.0.2", 80, 1)})
	}
	if n := len(d.sources); n > cfg.MaxTrackedSources {
		t.Fatalf("tracking %d sources after 20 distinct source IPs, want <= %d", n, cfg.MaxTrackedSources)
	}
}

// TestScanDetectorIgnoresNonPortProtocols confirms ICMP and other
// non-TCP/UDP traffic (which never has a meaningful port) cannot trigger
// either scan type.
func TestScanDetectorIgnoresNonPortProtocols(t *testing.T) {
	d := newScanDetector(testConfig())
	now := time.Unix(1000, 0)

	var records []trafficRecord
	for i := 0; i < 10; i++ {
		records = append(records, trafficRecord{SourceIP: "10.0.0.1", DestinationIP: "10.0.0.2", Protocol: "icmp", Packets: uint64(i + 1)})
	}
	if alerts := d.Observe(now, records); len(alerts) != 0 {
		t.Fatalf("got %d alerts for ICMP-only traffic, want 0: %+v", len(alerts), alerts)
	}
}

func TestScanAlertJSONSchema(t *testing.T) {
	alert := ScanAlert{
		SchemaVersion: scanAlertSchemaVersion,
		Kind:          "scan_alert",
		Type:          ScanAlertVertical,
		SourceIP:      "10.0.0.1",
		Protocol:      "tcp",
		TargetIP:      "10.0.0.2",
		DistinctCount: 5,
		WindowSeconds: 10,
		Timestamp:     time.Unix(1000, 0).UTC(),
	}
	data, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"schema_version", "kind", "type", "source_ip", "protocol", "target_ip", "distinct_count", "window_seconds", "timestamp"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing field %q in JSON output: %s", field, data)
		}
	}
	if _, ok := decoded["target_port"]; ok {
		t.Errorf("target_port should be omitted for a vertical alert: %s", data)
	}
}
