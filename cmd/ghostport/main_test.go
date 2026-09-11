package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseConfig(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cfg, err := parseConfig([]string{"--interface", "eth0", "--interval", "5s", "--json"})
		if err != nil {
			t.Fatalf("parseConfig returned error: %v", err)
		}
		if cfg.interfaceName != "eth0" || cfg.interval != 5*time.Second || !cfg.jsonOutput {
			t.Fatalf("unexpected config: %+v", cfg)
		}
	})

	t.Run("version does not require interface", func(t *testing.T) {
		cfg, err := parseConfig([]string{"--version"})
		if err != nil {
			t.Fatalf("parseConfig returned error: %v", err)
		}
		if !cfg.showVersion {
			t.Fatal("showVersion = false, want true")
		}
	})

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "missing interface", args: nil},
		{name: "invalid interval", args: []string{"--interface", "eth0", "--interval", "0s"}},
		{name: "extra argument", args: []string{"--interface", "eth0", "extra"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseConfig(tc.args); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSourceIPUsesNativeByteOrder(t *testing.T) {
	packetBytes := []byte{192, 0, 2, 10}
	key := binary.NativeEndian.Uint32(packetBytes)
	if got := sourceIP(key); got != "192.0.2.10" {
		t.Fatalf("sourceIP() = %q, want %q", got, "192.0.2.10")
	}
}

func TestWriteTrafficText(t *testing.T) {
	var output bytes.Buffer
	records := []trafficRecord{{SourceIP: "192.0.2.10", Packets: 7}}
	if err := writeTraffic(&output, records, false); err != nil {
		t.Fatalf("writeTraffic returned error: %v", err)
	}
	if !strings.Contains(output.String(), "192.0.2.10") || !strings.Contains(output.String(), "7") {
		t.Fatalf("unexpected text output: %q", output.String())
	}
}

func TestWriteTrafficJSON(t *testing.T) {
	var output bytes.Buffer
	records := []trafficRecord{{SourceIP: "198.51.100.4", Packets: 12}}
	if err := writeTraffic(&output, records, true); err != nil {
		t.Fatalf("writeTraffic returned error: %v", err)
	}

	var payload struct {
		Timestamp time.Time       `json:"timestamp"`
		Traffic   []trafficRecord `json:"traffic"`
	}
	if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
		t.Fatalf("decode JSON output: %v", err)
	}
	if payload.Timestamp.IsZero() || len(payload.Traffic) != 1 || payload.Traffic[0] != records[0] {
		t.Fatalf("unexpected JSON output: %+v", payload)
	}
}
