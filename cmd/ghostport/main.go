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
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
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

	scanDetection           bool
	scanWindow              time.Duration
	scanVerticalThreshold   int
	scanHorizontalThreshold int
	scanCooldown            time.Duration

	deliverEnabled    bool
	deliverEndpoint   string
	deliverTimeout    time.Duration
	deliverMaxRetries int
	deliverQueueSize  int

	status bool
}

// deliveryAuthTokenEnvVar is the only place an operator provides the
// bearer token used to authenticate to the delivery endpoint. It is never
// accepted as a CLI flag, since flags are visible to any local user who
// can list processes (e.g. `ps -ef`), while an environment variable is
// only visible to processes with permission to read this process's own
// environment.
const deliveryAuthTokenEnvVar = "GHOSTPORT_DELIVERY_TOKEN"

// resolveDeliveryToken separates the "is a token required and present"
// decision from reading the environment, so it can be unit tested without
// mutating process-wide environment state.
func resolveDeliveryToken(deliverEnabled bool, envValue string) (string, error) {
	if !deliverEnabled {
		return "", nil
	}
	if envValue == "" {
		return "", fmt.Errorf("%s environment variable is required with --deliver", deliveryAuthTokenEnvVar)
	}
	return envValue, nil
}

var version = "dev"

type trafficRecord struct {
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	Protocol        string `json:"protocol"`
	DestinationPort uint16 `json:"destination_port,omitempty"`
	Packets         uint64 `json:"packets"`
}

type trafficKey struct {
	SourceAddress      uint32
	DestinationAddress uint32
	DestinationPort    uint16
	Protocol           uint8
	Padding            uint8
}

func parseConfig(args []string) (config, error) {
	flags := flag.NewFlagSet("ghostport", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	defaultScan := defaultScanDetectorConfig()
	defaultDelivery := defaultEventDeliveryConfig()

	var cfg config
	flags.StringVar(&cfg.interfaceName, "interface", "", "network interface to monitor")
	flags.DurationVar(&cfg.interval, "interval", 3*time.Second, "telemetry reporting interval")
	flags.BoolVar(&cfg.jsonOutput, "json", false, "emit newline-delimited JSON")
	flags.BoolVar(&cfg.showVersion, "version", false, "print version and exit")
	flags.BoolVar(&cfg.scanDetection, "scan-detection", true, "detect and alert on vertical/horizontal port-scan patterns")
	flags.DurationVar(&cfg.scanWindow, "scan-window", defaultScan.Window, "how far back a probe still counts toward a scan threshold")
	flags.IntVar(&cfg.scanVerticalThreshold, "scan-vertical-threshold", defaultScan.VerticalPortThreshold, "distinct ports on one destination, from one source, within the window, to alert as a vertical scan")
	flags.IntVar(&cfg.scanHorizontalThreshold, "scan-horizontal-threshold", defaultScan.HorizontalHostThreshold, "distinct destinations on one port, from one source, within the window, to alert as a horizontal scan")
	flags.DurationVar(&cfg.scanCooldown, "scan-cooldown", defaultScan.Cooldown, "minimum time between repeated alerts for the same source and target")
	flags.BoolVar(&cfg.deliverEnabled, "deliver", false, "deliver scan alerts to an authenticated HTTPS endpoint (disabled by default)")
	flags.StringVar(&cfg.deliverEndpoint, "deliver-endpoint", "", "HTTPS endpoint to deliver scan alerts to; required with --deliver, must be an https:// URL")
	flags.DurationVar(&cfg.deliverTimeout, "deliver-timeout", defaultDelivery.Timeout, "per-attempt HTTP timeout for event delivery")
	flags.IntVar(&cfg.deliverMaxRetries, "deliver-max-retries", defaultDelivery.MaxRetries, "additional delivery attempts after the first, for retryable failures")
	flags.IntVar(&cfg.deliverQueueSize, "deliver-queue-size", defaultDelivery.QueueSize, "maximum alerts buffered waiting for delivery before new ones are dropped")
	flags.BoolVar(&cfg.status, "status", true, "emit a periodic status event (uptime, flow count, detector/delivery internals)")

	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if cfg.interfaceName == "" && !cfg.showVersion {
		return config{}, errors.New("--interface is required")
	}
	if cfg.interval <= 0 {
		return config{}, errors.New("--interval must be greater than zero")
	}
	if cfg.scanDetection {
		if cfg.scanWindow <= 0 {
			return config{}, errors.New("--scan-window must be greater than zero")
		}
		if cfg.scanVerticalThreshold <= 0 {
			return config{}, errors.New("--scan-vertical-threshold must be greater than zero")
		}
		if cfg.scanHorizontalThreshold <= 0 {
			return config{}, errors.New("--scan-horizontal-threshold must be greater than zero")
		}
		if cfg.scanCooldown <= 0 {
			return config{}, errors.New("--scan-cooldown must be greater than zero")
		}
	}
	if cfg.deliverEnabled {
		if cfg.deliverEndpoint == "" {
			return config{}, errors.New("--deliver-endpoint is required with --deliver")
		}
		if !strings.HasPrefix(cfg.deliverEndpoint, "https://") {
			return config{}, fmt.Errorf("--deliver-endpoint must be an https:// URL, got %q", cfg.deliverEndpoint)
		}
		if cfg.deliverTimeout <= 0 {
			return config{}, errors.New("--deliver-timeout must be greater than zero")
		}
		if cfg.deliverMaxRetries < 0 {
			return config{}, errors.New("--deliver-max-retries must not be negative")
		}
		if cfg.deliverQueueSize <= 0 {
			return config{}, errors.New("--deliver-queue-size must be greater than zero")
		}
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

	var delivery *eventDelivery
	if cfg.deliverEnabled {
		token, err := resolveDeliveryToken(cfg.deliverEnabled, os.Getenv(deliveryAuthTokenEnvVar))
		if err != nil {
			return fmt.Errorf("configuration: %w", err)
		}
		delivery = newEventDelivery(eventDeliveryConfig{
			Endpoint:      cfg.deliverEndpoint,
			Timeout:       cfg.deliverTimeout,
			MaxRetries:    cfg.deliverMaxRetries,
			QueueSize:     cfg.deliverQueueSize,
			ShutdownGrace: defaultEventDeliveryConfig().ShutdownGrace,
		}, token, &http.Client{Timeout: cfg.deliverTimeout})
		log.Printf("event delivery enabled: endpoint=%s timeout=%s max-retries=%d queue-size=%d",
			cfg.deliverEndpoint, cfg.deliverTimeout, cfg.deliverMaxRetries, cfg.deliverQueueSize)
	}

	iface, err := net.InterfaceByName(cfg.interfaceName)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", cfg.interfaceName, err)
	}

	if err := checkKernelSupportsTCX(); err != nil {
		return fmt.Errorf("kernel compatibility: %w", err)
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
		TrafficCounts  *ebpf.Map     `ebpf:"traffic_counts"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.IngressMonitor.Close()
	defer objs.TrafficCounts.Close()

	attachment, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressMonitor,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach ingress sensor to %s: %w (TCX requires Linux 6.6 or newer)", iface.Name, err)
	}
	defer attachment.Close()

	startTime := time.Now()
	if err := notifySystemd("READY=1"); err != nil {
		log.Printf("systemd readiness notification: %v", err)
	}

	log.Printf("sensor attached; reporting every %s", cfg.interval)

	var detector *scanDetector
	if cfg.scanDetection {
		detector = newScanDetector(scanDetectorConfig{
			Window:                  cfg.scanWindow,
			VerticalPortThreshold:   cfg.scanVerticalThreshold,
			HorizontalHostThreshold: cfg.scanHorizontalThreshold,
			Cooldown:                cfg.scanCooldown,
			MaxTrackedSources:       defaultScanDetectorConfig().MaxTrackedSources,
		})
		log.Printf("scan detection enabled: window=%s vertical-threshold=%d horizontal-threshold=%d cooldown=%s",
			cfg.scanWindow, cfg.scanVerticalThreshold, cfg.scanHorizontalThreshold, cfg.scanCooldown)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var deliveryWG sync.WaitGroup
	if delivery != nil {
		deliveryWG.Add(1)
		go func() {
			defer deliveryWG.Done()
			delivery.Run(ctx)
		}()
	}

	if wd := watchdogInterval(); wd > 0 {
		log.Printf("systemd watchdog enabled: pinging every %s", wd)
		go runWatchdog(ctx, wd)
	}

	kernel := kernelRelease()

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down and detaching sensor")
			if err := notifySystemd("STOPPING=1"); err != nil {
				log.Printf("systemd stopping notification: %v", err)
			}
			if delivery != nil {
				deliveryWG.Wait()
				if dropped := delivery.Dropped(); dropped > 0 {
					log.Printf("event delivery: dropped %d alerts over this run due to a full queue", dropped)
				}
			}
			return nil
		case <-ticker.C:
			records, err := readTraffic(objs.TrafficCounts)
			if err != nil {
				return err
			}
			if err := writeTraffic(os.Stdout, records, cfg.jsonOutput); err != nil {
				return err
			}
			if detector != nil {
				for _, alert := range detector.Observe(time.Now(), records) {
					if err := writeScanAlert(os.Stdout, alert, cfg.jsonOutput); err != nil {
						return err
					}
					if delivery != nil {
						delivery.Enqueue(alert)
					}
				}
			}
			if cfg.status {
				status := SensorStatus{
					SchemaVersion:        statusSchemaVersion,
					Kind:                 "status",
					Interface:            iface.Name,
					KernelRelease:        kernel,
					UptimeSeconds:        time.Since(startTime).Seconds(),
					TrafficFlows:         len(records),
					TrafficFlowsMax:      int(objs.TrafficCounts.MaxEntries()),
					ScanDetectionEnabled: detector != nil,
					DeliveryEnabled:      delivery != nil,
					Timestamp:            time.Now().UTC(),
				}
				if detector != nil {
					status.ScanTrackedSources = detector.TrackedSources()
				}
				if delivery != nil {
					status.DeliveryQueued = delivery.QueueDepth()
					status.DeliveryDropped = delivery.Dropped()
				}
				if err := writeStatus(os.Stdout, status, cfg.jsonOutput); err != nil {
					return err
				}
			}
		}
	}
}

// runWatchdog pings systemd's watchdog at the given interval until ctx is
// done. Errors are logged, not fatal: a failed watchdog ping should not
// crash the sensor, though it may cause systemd to eventually restart it,
// which is the intended failure mode for a genuinely hung process.
func runWatchdog(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := notifySystemd("WATCHDOG=1"); err != nil {
				log.Printf("systemd watchdog notification: %v", err)
			}
		}
	}
}

func sourceIP(key uint32) string {
	ipBytes := make([]byte, net.IPv4len)
	binary.NativeEndian.PutUint32(ipBytes, key)
	return net.IP(ipBytes).String()
}

func protocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return fmt.Sprintf("ip-%d", protocol)
	}
}

func readTraffic(packetCounts *ebpf.Map) ([]trafficRecord, error) {
	var records []trafficRecord
	var key trafficKey
	var value uint64
	iter := packetCounts.Iterate()
	for iter.Next(&key, &value) {
		records = append(records, trafficRecord{
			SourceIP: sourceIP(key.SourceAddress), DestinationIP: sourceIP(key.DestinationAddress),
			Protocol: protocolName(key.Protocol), DestinationPort: key.DestinationPort, Packets: value,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("read telemetry map: %w", err)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].SourceIP != records[j].SourceIP {
			return records[i].SourceIP < records[j].SourceIP
		}
		if records[i].DestinationIP != records[j].DestinationIP {
			return records[i].DestinationIP < records[j].DestinationIP
		}
		return records[i].DestinationPort < records[j].DestinationPort
	})
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
		if _, err := fmt.Fprintf(w, "Source: %-15s | Destination: %-15s | Protocol: %-5s | Port: %-5d | Packets: %d\n", record.SourceIP, record.DestinationIP, record.Protocol, record.DestinationPort, record.Packets); err != nil {
			return fmt.Errorf("write telemetry: %w", err)
		}
	}
	return nil
}

func writeScanAlert(w io.Writer, alert ScanAlert, jsonOutput bool) error {
	if jsonOutput {
		if err := json.NewEncoder(w).Encode(alert); err != nil {
			return fmt.Errorf("write JSON scan alert: %w", err)
		}
		return nil
	}

	var err error
	switch alert.Type {
	case ScanAlertVertical:
		_, err = fmt.Fprintf(w, "SCAN ALERT: %s probed %d distinct %s ports on %s within %gs\n",
			alert.SourceIP, alert.DistinctCount, alert.Protocol, alert.TargetIP, alert.WindowSeconds)
	case ScanAlertHorizontal:
		_, err = fmt.Fprintf(w, "SCAN ALERT: %s probed %s/%d across %d distinct destinations within %gs\n",
			alert.SourceIP, alert.Protocol, alert.TargetPort, alert.DistinctCount, alert.WindowSeconds)
	default:
		_, err = fmt.Fprintf(w, "SCAN ALERT: %s (%s)\n", alert.SourceIP, alert.Type)
	}
	if err != nil {
		return fmt.Errorf("write scan alert: %w", err)
	}
	return nil
}
