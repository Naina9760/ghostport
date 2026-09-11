package main

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	log.Println("GhostPort controller initialized. Loading eBPF bytecode and maps...")

	spec, err := ebpf.LoadCollectionSpec("cmd/ghostport/ghostport.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF collection spec: %v", err)
	}

	var objs struct {
		IngressMonitor *ebpf.Program `ebpf:"ghostport_ingress_monitor"`
		PacketCounts   *ebpf.Map     `ebpf:"packet_counts"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign eBPF objects: %v", err)
	}
	defer objs.IngressMonitor.Close()
	defer objs.PacketCounts.Close()

	log.Println("Successfully loaded GhostPort into kernel space. Reading telemetry map...")

	// Periodically read from the eBPF map
	for {
		time.Sleep(3 * time.Second)

		var key uint32
		var val uint64
		iter := objs.PacketCounts.Iterate()

		log.Println("--- GhostPort Honey-Mesh Traffic Telemetry ---")
		for iter.Next(&key, &val) {
			ipBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(ipBytes, key)
			ipStr := net.IP(ipBytes).String()
			log.Printf("Source IP: %-15s | Packets Intercepted: %d\n", ipStr, val)
		}
	}
}
