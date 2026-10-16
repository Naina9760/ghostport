package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// statusSchemaVersion is bumped whenever a field is added, removed, or
// changes meaning in SensorStatus.
const statusSchemaVersion = 1

// SensorStatus is a periodic structured event reporting GhostPort's own
// health, distinct from the traffic it observes: uptime, attachment state,
// how full the BPF map is, and (when the relevant features are enabled)
// scan-detector and event-delivery internals. It contains no traffic data
// of its own.
type SensorStatus struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"` // always "status"

	Interface     string  `json:"interface"`
	KernelRelease string  `json:"kernel_release,omitempty"`
	UptimeSeconds float64 `json:"uptime_seconds"`

	TrafficFlows    int `json:"traffic_flows"`
	TrafficFlowsMax int `json:"traffic_flows_max"`

	ScanDetectionEnabled bool `json:"scan_detection_enabled"`
	ScanTrackedSources   int  `json:"scan_tracked_sources,omitempty"`

	DeliveryEnabled bool   `json:"delivery_enabled"`
	DeliveryQueued  int    `json:"delivery_queued,omitempty"`
	DeliveryDropped uint64 `json:"delivery_dropped,omitempty"`

	Timestamp time.Time `json:"timestamp"`
}

func writeStatus(w io.Writer, status SensorStatus, jsonOutput bool) error {
	if jsonOutput {
		if err := json.NewEncoder(w).Encode(status); err != nil {
			return fmt.Errorf("write JSON status: %w", err)
		}
		return nil
	}

	if _, err := fmt.Fprintf(w, "STATUS: interface=%s uptime=%s flows=%d/%d",
		status.Interface, time.Duration(status.UptimeSeconds*float64(time.Second)).Round(time.Second),
		status.TrafficFlows, status.TrafficFlowsMax); err != nil {
		return fmt.Errorf("write status: %w", err)
	}
	if status.ScanDetectionEnabled {
		if _, err := fmt.Fprintf(w, " scan-tracked-sources=%d", status.ScanTrackedSources); err != nil {
			return fmt.Errorf("write status: %w", err)
		}
	}
	if status.DeliveryEnabled {
		if _, err := fmt.Fprintf(w, " delivery-queued=%d delivery-dropped=%d", status.DeliveryQueued, status.DeliveryDropped); err != nil {
			return fmt.Errorf("write status: %w", err)
		}
	}
	_, err := fmt.Fprintln(w)
	if err != nil {
		return fmt.Errorf("write status: %w", err)
	}
	return nil
}
