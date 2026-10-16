package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testStatus() SensorStatus {
	return SensorStatus{
		SchemaVersion:        statusSchemaVersion,
		Kind:                 "status",
		Interface:            "eth0",
		KernelRelease:        "6.8.0-generic",
		UptimeSeconds:        125,
		TrafficFlows:         12,
		TrafficFlowsMax:      4096,
		ScanDetectionEnabled: true,
		ScanTrackedSources:   3,
		DeliveryEnabled:      true,
		DeliveryQueued:       2,
		DeliveryDropped:      1,
		Timestamp:            time.Unix(1000, 0).UTC(),
	}
}

func TestWriteStatusJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := writeStatus(&buf, testStatus(), true); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	for _, field := range []string{
		"schema_version", "kind", "interface", "kernel_release", "uptime_seconds",
		"traffic_flows", "traffic_flows_max", "scan_detection_enabled",
		"scan_tracked_sources", "delivery_enabled", "delivery_queued",
		"delivery_dropped", "timestamp",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing field %q: %s", field, buf.String())
		}
	}
	if decoded["kind"] != "status" {
		t.Errorf("kind = %v, want \"status\"", decoded["kind"])
	}
}

func TestWriteStatusJSONOmitsDisabledFeatureFields(t *testing.T) {
	status := testStatus()
	status.ScanDetectionEnabled = false
	status.ScanTrackedSources = 0
	status.DeliveryEnabled = false
	status.DeliveryQueued = 0
	status.DeliveryDropped = 0

	var buf bytes.Buffer
	if err := writeStatus(&buf, status, true); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	for _, field := range []string{"scan_tracked_sources", "delivery_queued", "delivery_dropped"} {
		if strings.Contains(buf.String(), field) {
			t.Errorf("expected %q to be omitted when the corresponding feature is disabled: %s", field, buf.String())
		}
	}
}

func TestWriteStatusText(t *testing.T) {
	var buf bytes.Buffer
	if err := writeStatus(&buf, testStatus(), false); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"eth0", "12/4096", "scan-tracked-sources=3", "delivery-queued=2", "delivery-dropped=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("text status output missing %q: %q", want, out)
		}
	}
}
