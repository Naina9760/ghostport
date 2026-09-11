package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed ghostport.bpf.o
var bpfObject []byte

type config struct {
	interfaceName string
	interval      time.Duration
	jsonOutput    bool
	showVersion   bool
}

var version = "dev"

type trafficRecord struct {
	SourceIP string `json:"source_ip"`
	Packets  uint64 `json:"packets"`
}

func parseConfig(args []string) (config, error) {
	flags := flag.NewFlagSet("ghostport", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	var cfg config
	flags.StringVar(&cfg.interfaceName, "interface", "", "network interface to monitor")
	flags.DurationVar(&cfg.interval, "interval", 3*time.Second, "telemetry reporting interval")
	flags.BoolVar(&cfg.jsonOutput, "json", false, "emit newline-delimited JSON")
	flags.BoolVar(&cfg.showVersion, "version", false, "print version and exit")

	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if cfg.interfaceName == "" && !cfg.showVersion {
		return config{}, errors.New("--interface is required")
	}
	if cfg.interval <= 0 {
		return config{}, errors.New("--interval must be greater than zero")
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	return cfg, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if cfg.showVersion {
		fmt.Printf("ghostport %s\n", version)
		return nil
	}

	iface, err := net.InterfaceByName(cfg.interfaceName)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", cfg.interfaceName, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	log.Printf("loading GhostPort sensor on interface %s (index %d)", iface.Name, iface.Index)

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return fmt.Errorf("load eBPF collection spec: %w", err)
	}

	var objs struct {
		IngressMonitor *ebpf.Program `ebpf:"ghostport_ingress_monitor"`
		PacketCounts   *ebpf.Map     `ebpf:"packet_counts"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.IngressMonitor.Close()
	defer objs.PacketCounts.Close()

	attachment, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressMonitor,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach ingress sensor to %s: %w (TCX requires Linux 6.6 or newer)", iface.Name, err)
	}
	defer attachment.Close()

	log.Printf("sensor attached; reporting every %s", cfg.interval)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down and detaching sensor")
			return nil
		case <-ticker.C:
			records, err := readTraffic(objs.PacketCounts)
			if err != nil {
				return err
			}
			if err := writeTraffic(os.Stdout, records, cfg.jsonOutput); err != nil {
				return err
			}
		}
	}
}

func sourceIP(key uint32) string {
	ipBytes := make([]byte, net.IPv4len)
	binary.NativeEndian.PutUint32(ipBytes, key)
	return net.IP(ipBytes).String()
}

func readTraffic(packetCounts *ebpf.Map) ([]trafficRecord, error) {
	var records []trafficRecord
	var key uint32
	var value uint64
	iter := packetCounts.Iterate()
	for iter.Next(&key, &value) {
		records = append(records, trafficRecord{SourceIP: sourceIP(key), Packets: value})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("read telemetry map: %w", err)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].SourceIP < records[j].SourceIP })
	return records, nil
}

func writeTraffic(w io.Writer, records []trafficRecord, jsonOutput bool) error {
	if jsonOutput {
		payload := struct {
			Timestamp time.Time       `json:"timestamp"`
			Traffic   []trafficRecord `json:"traffic"`
		}{Timestamp: time.Now().UTC(), Traffic: records}
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			return fmt.Errorf("write JSON telemetry: %w", err)
		}
		return nil
	}

	if _, err := fmt.Fprintln(w, "--- GhostPort Traffic Telemetry ---"); err != nil {
		return fmt.Errorf("write telemetry header: %w", err)
	}
	if len(records) == 0 {
		_, err := fmt.Fprintln(w, "No IPv4 traffic observed.")
		return err
	}
	for _, record := range records {
		if _, err := fmt.Fprintf(w, "Source IP: %-15s | Packets observed: %d\n", record.SourceIP, record.Packets); err != nil {
			return fmt.Errorf("write telemetry: %w", err)
		}
	}
	return nil
}
