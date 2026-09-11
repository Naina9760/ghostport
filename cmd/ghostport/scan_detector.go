package main

import (
	"strconv"
	"time"
)

// scanAlertSchemaVersion is bumped whenever a field is added, removed, or
// changes meaning in ScanAlert, so downstream consumers of the
// newline-delimited JSON stream can detect a change they need to handle.
const scanAlertSchemaVersion = 1

// ScanAlertType distinguishes the two scan shapes GhostPort detects.
type ScanAlertType string

const (
	// ScanAlertVertical: one source IP touching many distinct destination
	// ports on a single destination IP.
	ScanAlertVertical ScanAlertType = "vertical"
	// ScanAlertHorizontal: one source IP touching the same destination
	// port across many distinct destination IPs.
	ScanAlertHorizontal ScanAlertType = "horizontal"
)

// ScanAlert is the structured event GhostPort emits when a source crosses a
// scan threshold. It never contains packet payload data, only the same
// address/port/protocol metadata already reported in traffic telemetry.
type ScanAlert struct {
	SchemaVersion int           `json:"schema_version"`
	Kind          string        `json:"kind"` // always "scan_alert"; disambiguates from a traffic snapshot object in the same NDJSON stream
	Type          ScanAlertType `json:"type"`
	SourceIP      string        `json:"source_ip"`
	Protocol      string        `json:"protocol"`
	TargetIP      string        `json:"target_ip,omitempty"`   // set for a vertical alert: the one destination being probed
	TargetPort    uint16        `json:"target_port,omitempty"` // set for a horizontal alert: the one port being probed
	DistinctCount int           `json:"distinct_count"`        // distinct ports (vertical) or distinct hosts (horizontal) observed within the window
	WindowSeconds float64       `json:"window_seconds"`
	Timestamp     time.Time     `json:"timestamp"`
}

// scanDetectorConfig holds the tunable knobs for scan detection. All are
// required to be positive; parseConfig validates this the same way it
// validates --interval.
type scanDetectorConfig struct {
	// Window is how far back in time a touch (a new or increased packet
	// count for a source/destination/port) still counts toward a
	// threshold.
	Window time.Duration
	// VerticalPortThreshold is how many distinct destination ports on one
	// destination IP, from one source, within Window, constitute a
	// vertical scan.
	VerticalPortThreshold int
	// HorizontalHostThreshold is how many distinct destination IPs on one
	// port, from one source, within Window, constitute a horizontal scan.
	HorizontalHostThreshold int
	// Cooldown is the minimum time between repeated alerts for the same
	// (source, type, target) tuple, so a sustained scan produces one
	// alert per cooldown period rather than one alert per packet.
	Cooldown time.Duration
	// MaxTrackedSources bounds userspace memory: once this many source
	// IPs have activity tracked, the least-recently-active source is
	// evicted to make room, the same trade-off the BPF map itself makes
	// with BPF_MAP_TYPE_LRU_HASH.
	MaxTrackedSources int
}

// defaultScanDetectorConfig matches the CLI flag defaults in main.go.
func defaultScanDetectorConfig() scanDetectorConfig {
	return scanDetectorConfig{
		Window:                  30 * time.Second,
		VerticalPortThreshold:   20,
		HorizontalHostThreshold: 20,
		Cooldown:                60 * time.Second,
		MaxTrackedSources:       4096,
	}
}

type flowKey struct {
	sourceIP string
	destIP   string
	protocol string
	destPort uint16
}

type timestampedSet[K comparable] map[K]time.Time

func (s timestampedSet[K]) prune(cutoff time.Time) {
	for k, seen := range s {
		if seen.Before(cutoff) {
			delete(s, k)
		}
	}
}

// sourceActivity tracks, for one source IP, what it has touched recently
// enough to still be inside the detection window.
type sourceActivity struct {
	lastActive time.Time
	// portsByDest[destIP] is the set of destination ports touched on that
	// destination, each with its last-touch time, for vertical detection.
	portsByDest map[string]timestampedSet[uint16]
	// destsByPort[destPort] is the set of destination IPs touched on that
	// port, each with its last-touch time, for horizontal detection.
	destsByPort map[uint16]timestampedSet[string]
}

// scanDetector observes periodic traffic snapshots (already-decoded
// trafficRecord slices, the same data writeTraffic prints) and emits
// ScanAlerts. It holds no reference to the eBPF map or any packet data,
// so it is fully unit-testable with synthetic input and a controlled
// clock, and it can never see a packet payload because trafficRecord
// never contains one.
type scanDetector struct {
	cfg scanDetectorConfig

	// lastCount is rebuilt from scratch on every Observe call using only
	// the flows present in that call's records, so it can never grow
	// larger than the number of flows currently in the BPF map (itself
	// bounded by LRU_HASH's max_entries). This is what makes counter
	// deltas safe: a flow that has vanished from the map cannot leave a
	// stale, ever-growing entry behind.
	lastCount map[flowKey]uint64

	sources map[string]*sourceActivity

	lastVerticalAlert   map[[2]string]time.Time // [sourceIP, targetIP] -> last alert time
	lastHorizontalAlert map[string]time.Time    // sourceIP+"|"+protocol+"|"+port -> last alert time
}

func newScanDetector(cfg scanDetectorConfig) *scanDetector {
	return &scanDetector{
		cfg:                 cfg,
		lastCount:           make(map[flowKey]uint64),
		sources:             make(map[string]*sourceActivity),
		lastVerticalAlert:   make(map[[2]string]time.Time),
		lastHorizontalAlert: make(map[string]time.Time),
	}
}

// Observe processes one traffic snapshot and returns any alerts that just
// crossed a threshold (subject to cooldown). Calling it repeatedly with a
// monotonically non-decreasing now is the expected usage; it is not safe
// for concurrent use, matching how it is driven from main.go's single
// reporting loop.
func (d *scanDetector) Observe(now time.Time, records []trafficRecord) []ScanAlert {
	d.pruneSources(now)

	touches := d.computeTouches(records)

	var alerts []ScanAlert
	for _, t := range touches {
		alerts = append(alerts, d.recordTouch(now, t)...)
	}
	return alerts
}

type touch struct {
	sourceIP, destIP, protocol string
	destPort                   uint16
}

// computeTouches turns cumulative packet counts into "did this flow see
// new traffic since the last poll" events, replacing d.lastCount wholesale
// so it can never accumulate entries for flows that stopped appearing.
func (d *scanDetector) computeTouches(records []trafficRecord) []touch {
	next := make(map[flowKey]uint64, len(records))
	var touches []touch

	for _, rec := range records {
		if rec.Protocol != "tcp" && rec.Protocol != "udp" {
			continue // a port only means something for TCP/UDP
		}
		key := flowKey{sourceIP: rec.SourceIP, destIP: rec.DestinationIP, protocol: rec.Protocol, destPort: rec.DestinationPort}
		next[key] = rec.Packets

		prev, existed := d.lastCount[key]
		switch {
		case !existed:
			touches = append(touches, touch{rec.SourceIP, rec.DestinationIP, rec.Protocol, rec.DestinationPort})
		case rec.Packets > prev:
			touches = append(touches, touch{rec.SourceIP, rec.DestinationIP, rec.Protocol, rec.DestinationPort})
		case rec.Packets < prev:
			// The cumulative counter went backwards, which only happens
			// if the BPF map evicted and restarted this flow's entry.
			// Treat it as a fresh touch rather than computing a negative
			// delta.
			touches = append(touches, touch{rec.SourceIP, rec.DestinationIP, rec.Protocol, rec.DestinationPort})
		}
	}

	d.lastCount = next
	return touches
}

func (d *scanDetector) recordTouch(now time.Time, t touch) []ScanAlert {
	src := d.sources[t.sourceIP]
	if src == nil {
		if len(d.sources) >= d.cfg.MaxTrackedSources {
			d.evictOldestSource()
		}
		src = &sourceActivity{
			portsByDest: make(map[string]timestampedSet[uint16]),
			destsByPort: make(map[uint16]timestampedSet[string]),
		}
		d.sources[t.sourceIP] = src
	}
	src.lastActive = now

	if src.portsByDest[t.destIP] == nil {
		src.portsByDest[t.destIP] = make(timestampedSet[uint16])
	}
	src.portsByDest[t.destIP][t.destPort] = now

	if src.destsByPort[t.destPort] == nil {
		src.destsByPort[t.destPort] = make(timestampedSet[string])
	}
	src.destsByPort[t.destPort][t.destIP] = now

	var alerts []ScanAlert

	cutoff := now.Add(-d.cfg.Window)
	src.portsByDest[t.destIP].prune(cutoff)
	if n := len(src.portsByDest[t.destIP]); n >= d.cfg.VerticalPortThreshold {
		alertKey := [2]string{t.sourceIP, t.destIP}
		if now.Sub(d.lastVerticalAlert[alertKey]) >= d.cfg.Cooldown {
			d.lastVerticalAlert[alertKey] = now
			alerts = append(alerts, ScanAlert{
				SchemaVersion: scanAlertSchemaVersion,
				Kind:          "scan_alert",
				Type:          ScanAlertVertical,
				SourceIP:      t.sourceIP,
				Protocol:      t.protocol,
				TargetIP:      t.destIP,
				DistinctCount: n,
				WindowSeconds: d.cfg.Window.Seconds(),
				Timestamp:     now,
			})
		}
	}

	src.destsByPort[t.destPort].prune(cutoff)
	if n := len(src.destsByPort[t.destPort]); n >= d.cfg.HorizontalHostThreshold {
		alertKey := t.sourceIP + "|" + t.protocol + "|" + strconv.Itoa(int(t.destPort))
		if now.Sub(d.lastHorizontalAlert[alertKey]) >= d.cfg.Cooldown {
			d.lastHorizontalAlert[alertKey] = now
			alerts = append(alerts, ScanAlert{
				SchemaVersion: scanAlertSchemaVersion,
				Kind:          "scan_alert",
				Type:          ScanAlertHorizontal,
				SourceIP:      t.sourceIP,
				Protocol:      t.protocol,
				TargetPort:    t.destPort,
				DistinctCount: n,
				WindowSeconds: d.cfg.Window.Seconds(),
				Timestamp:     now,
			})
		}
	}

	return alerts
}

// pruneSources removes sources with no activity in the last window, and
// prunes each remaining source's per-destination and per-port sets, so
// memory reflects only what is still inside the detection window.
func (d *scanDetector) pruneSources(now time.Time) {
	cutoff := now.Add(-d.cfg.Window)
	for ip, src := range d.sources {
		if src.lastActive.Before(cutoff) {
			delete(d.sources, ip)
			continue
		}
		for dest, ports := range src.portsByDest {
			ports.prune(cutoff)
			if len(ports) == 0 {
				delete(src.portsByDest, dest)
			}
		}
		for port, dests := range src.destsByPort {
			dests.prune(cutoff)
			if len(dests) == 0 {
				delete(src.destsByPort, port)
			}
		}
	}
}

// evictOldestSource drops the least-recently-active source to keep
// MaxTrackedSources as a hard cap on userspace memory, mirroring the BPF
// map's own LRU eviction under sustained pressure from many distinct
// source IPs.
func (d *scanDetector) evictOldestSource() {
	var oldestIP string
	var oldestTime time.Time
	first := true
	for ip, src := range d.sources {
		if first || src.lastActive.Before(oldestTime) {
			oldestIP, oldestTime = ip, src.lastActive
			first = false
		}
	}
	if !first {
		delete(d.sources, oldestIP)
	}
}
