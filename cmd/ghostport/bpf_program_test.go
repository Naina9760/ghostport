package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// These tests load the real compiled ghostport.bpf.o and run it in the
// kernel via BPF_PROG_TEST_RUN (github.com/cilium/ebpf's Program.Test),
// exercising the verifier and the actual parsing/map logic against
// synthetic packets. They require Linux and root (or CAP_BPF); on any
// other environment they skip rather than fail, so `go test ./...` stays
// green on a contributor's workstation and only runs for real under sudo
// on Linux CI.

const (
	ethTypeIPv4 = 0x0800
	ethTypeARP  = 0x0806

	ipProtoICMP = 1
	ipProtoTCP  = 6
	ipProtoUDP  = 17

	ipFragOffsetMask = 0x1FFF
	ipFragMoreFlag   = 0x2000

	tcActOK = 0
)

func loadIngressProgram(t *testing.T) (*ebpf.Program, *ebpf.Map) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("loading eBPF programs requires Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs requires root or CAP_BPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock limit: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		t.Fatalf("load eBPF collection spec: %v", err)
	}

	var objs struct {
		IngressMonitor *ebpf.Program `ebpf:"ghostport_ingress_monitor"`
		TrafficCounts  *ebpf.Map     `ebpf:"traffic_counts"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("load and assign eBPF objects: %v", err)
	}
	t.Cleanup(func() {
		objs.IngressMonitor.Close()
		objs.TrafficCounts.Close()
	})

	return objs.IngressMonitor, objs.TrafficCounts
}

// le32 mirrors how the raw packet bytes for an IPv4 address end up as a
// trafficKey field: the eBPF program copies iph->saddr/daddr without a
// byte swap, and the Go side (sourceIP in main.go) decodes the map key
// with the host's native byte order. On the little-endian hosts this
// project supports (amd64, arm64), that round trip is equivalent to
// reading the address bytes as little-endian.
func le32(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

func ethernetHeader(ethType uint16) []byte {
	h := make([]byte, 14)
	binary.BigEndian.PutUint16(h[12:14], ethType)
	return h
}

type ipv4Options struct {
	protocol        byte
	src, dst        net.IP
	ihlWords        byte // 0 defaults to 5 (20-byte header, no options)
	fragOffsetWords uint16
	moreFragments   bool
	payload         []byte
}

func ipv4Packet(o ipv4Options) []byte {
	ihl := o.ihlWords
	if ihl == 0 {
		ihl = 5
	}
	headerLen := int(ihl) * 4
	header := make([]byte, headerLen)

	header[0] = 0x40 | ihl
	binary.BigEndian.PutUint16(header[2:4], uint16(headerLen+len(o.payload)))

	fragField := o.fragOffsetWords & ipFragOffsetMask
	if o.moreFragments {
		fragField |= ipFragMoreFlag
	}
	binary.BigEndian.PutUint16(header[6:8], fragField)

	header[8] = 64 // TTL
	header[9] = o.protocol
	copy(header[12:16], o.src.To4())
	copy(header[16:20], o.dst.To4())

	packet := append([]byte{}, ethernetHeader(ethTypeIPv4)...)
	packet = append(packet, header...)
	packet = append(packet, o.payload...)
	return packet
}

func tcpSegment(dport uint16) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], 12345)
	binary.BigEndian.PutUint16(h[2:4], dport)
	h[12] = 5 << 4 // data offset, no options
	return h
}

func udpSegment(dport uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], 54321)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], 8)
	return h
}

func runProgram(t *testing.T, prog *ebpf.Program, packet []byte) uint32 {
	t.Helper()
	ret, _, err := prog.Test(packet)
	if err != nil {
		t.Fatalf("run program: %v", err)
	}
	return ret
}

func lookupCount(t *testing.T, m *ebpf.Map, src, dst net.IP, protocol byte, dport uint16) (uint64, bool) {
	t.Helper()
	key := trafficKey{
		SourceAddress:      le32(src),
		DestinationAddress: le32(dst),
		DestinationPort:    dport,
		Protocol:           protocol,
	}
	var value uint64
	if err := m.Lookup(&key, &value); err != nil {
		return 0, false
	}
	return value, true
}

func mapEntryCount(t *testing.T, m *ebpf.Map) int {
	t.Helper()
	var (
		key   trafficKey
		value uint64
		n     int
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		n++
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate map: %v", err)
	}
	return n
}

func TestBPFProgramCountsWellFormedTCP(t *testing.T) {
	prog, m := loadIngressProgram(t)
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	packet := ipv4Packet(ipv4Options{protocol: ipProtoTCP, src: src, dst: dst, payload: tcpSegment(22)})

	if ret := runProgram(t, prog, packet); ret != tcActOK {
		t.Fatalf("program returned %d, want TC_ACT_OK", ret)
	}
	count, ok := lookupCount(t, m, src, dst, ipProtoTCP, 22)
	if !ok || count != 1 {
		t.Fatalf("lookup = (%d, %v), want (1, true)", count, ok)
	}
}

func TestBPFProgramCountsWellFormedUDP(t *testing.T) {
	prog, m := loadIngressProgram(t)
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	packet := ipv4Packet(ipv4Options{protocol: ipProtoUDP, src: src, dst: dst, payload: udpSegment(53)})

	runProgram(t, prog, packet)
	count, ok := lookupCount(t, m, src, dst, ipProtoUDP, 53)
	if !ok || count != 1 {
		t.Fatalf("lookup = (%d, %v), want (1, true)", count, ok)
	}
}

func TestBPFProgramAccumulatesRepeatedPackets(t *testing.T) {
	prog, m := loadIngressProgram(t)
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	packet := ipv4Packet(ipv4Options{protocol: ipProtoTCP, src: src, dst: dst, payload: tcpSegment(443)})

	const sends = 5
	for i := 0; i < sends; i++ {
		runProgram(t, prog, packet)
	}
	count, ok := lookupCount(t, m, src, dst, ipProtoTCP, 443)
	if !ok || count != sends {
		t.Fatalf("lookup = (%d, %v), want (%d, true)", count, ok, sends)
	}
}

func TestBPFProgramIgnoresNonIPv4(t *testing.T) {
	prog, m := loadIngressProgram(t)
	arp := append(ethernetHeader(ethTypeARP), make([]byte, 28)...)

	if ret := runProgram(t, prog, arp); ret != tcActOK {
		t.Fatalf("program returned %d, want TC_ACT_OK", ret)
	}
	if n := mapEntryCount(t, m); n != 0 {
		t.Fatalf("map has %d entries, want 0 for a non-IPv4 packet", n)
	}
}

func TestBPFProgramHandlesTruncatedEthernetOnlyFrame(t *testing.T) {
	prog, m := loadIngressProgram(t)
	frame := ethernetHeader(ethTypeIPv4) // no IP header at all

	if ret := runProgram(t, prog, frame); ret != tcActOK {
		t.Fatalf("program returned %d, want TC_ACT_OK", ret)
	}
	if n := mapEntryCount(t, m); n != 0 {
		t.Fatalf("map has %d entries, want 0 for a frame with no IP header", n)
	}
}

func TestBPFProgramHandlesTruncatedIPHeader(t *testing.T) {
	prog, m := loadIngressProgram(t)
	frame := append(ethernetHeader(ethTypeIPv4), make([]byte, 10)...) // 10 of 20 IPv4 header bytes

	if ret := runProgram(t, prog, frame); ret != tcActOK {
		t.Fatalf("program returned %d, want TC_ACT_OK", ret)
	}
	if n := mapEntryCount(t, m); n != 0 {
		t.Fatalf("map has %d entries, want 0 for a truncated IP header", n)
	}
}

func TestBPFProgramHandlesTruncatedTransportHeader(t *testing.T) {
	prog, m := loadIngressProgram(t)
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	// Declares TCP but only supplies 4 of the required 20 transport bytes.
	packet := ipv4Packet(ipv4Options{protocol: ipProtoTCP, src: src, dst: dst, payload: tcpSegment(80)[:4]})

	if ret := runProgram(t, prog, packet); ret != tcActOK {
		t.Fatalf("program returned %d, want TC_ACT_OK", ret)
	}
	if n := mapEntryCount(t, m); n != 0 {
		t.Fatalf("map has %d entries, want 0 for a truncated TCP header", n)
	}
}

func TestBPFProgramHandlesIPv4Options(t *testing.T) {
	prog, m := loadIngressProgram(t)
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	packet := ipv4Packet(ipv4Options{
		protocol: ipProtoTCP,
		src:      src,
		dst:      dst,
		ihlWords: 6, // 24-byte header: 4 bytes of IPv4 options
		payload:  tcpSegment(8080),
	})

	runProgram(t, prog, packet)
	count, ok := lookupCount(t, m, src, dst, ipProtoTCP, 8080)
	if !ok || count != 1 {
		t.Fatalf("lookup = (%d, %v), want (1, true) with IPv4 options present", count, ok)
	}
}

func TestBPFProgramSkipsPortForNonInitialFragment(t *testing.T) {
	prog, m := loadIngressProgram(t)
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	// Non-initial fragment: offset != 0, and the "payload" is fragment
	// data, not a UDP header. If the parser mistook this for a transport
	// header it would record a bogus, non-zero destination port.
	garbage := bytes.Repeat([]byte{0xFF}, 16)
	packet := ipv4Packet(ipv4Options{
		protocol:        ipProtoUDP,
		src:             src,
		dst:             dst,
		fragOffsetWords: 185, // byte offset 1480, a plausible second fragment
		payload:         garbage,
	})

	runProgram(t, prog, packet)
	count, ok := lookupCount(t, m, src, dst, ipProtoUDP, 0)
	if !ok || count != 1 {
		t.Fatalf("lookup(dport=0) = (%d, %v), want (1, true) for a non-initial fragment", count, ok)
	}
}

func TestBPFProgramParsesPortOnInitialFragment(t *testing.T) {
	prog, m := loadIngressProgram(t)
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	// Initial fragment: offset == 0 but more-fragments is set. A real
	// transport header is present and should still be parsed.
	packet := ipv4Packet(ipv4Options{
		protocol:      ipProtoUDP,
		src:           src,
		dst:           dst,
		moreFragments: true,
		payload:       udpSegment(53),
	})

	runProgram(t, prog, packet)
	count, ok := lookupCount(t, m, src, dst, ipProtoUDP, 53)
	if !ok || count != 1 {
		t.Fatalf("lookup = (%d, %v), want (1, true) for the initial fragment", count, ok)
	}
}

func TestBPFProgramIgnoresICMPPort(t *testing.T) {
	prog, m := loadIngressProgram(t)
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	packet := ipv4Packet(ipv4Options{protocol: ipProtoICMP, src: src, dst: dst, payload: make([]byte, 8)})

	runProgram(t, prog, packet)
	count, ok := lookupCount(t, m, src, dst, ipProtoICMP, 0)
	if !ok || count != 1 {
		t.Fatalf("lookup = (%d, %v), want (1, true) for ICMP with no port", count, ok)
	}
}

// TestReadTrafficReflectsRealKernelState exercises the full path from
// synthetic packets through the real, kernel-verified program into the
// real map, and then through readTraffic's conversion and sort, which
// unit tests alone (with a fake map) cannot cover.
func TestReadTrafficReflectsRealKernelState(t *testing.T) {
	prog, m := loadIngressProgram(t)
	srcA, srcB := net.ParseIP("10.0.0.9"), net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")

	runProgram(t, prog, ipv4Packet(ipv4Options{protocol: ipProtoTCP, src: srcA, dst: dst, payload: tcpSegment(443)}))
	runProgram(t, prog, ipv4Packet(ipv4Options{protocol: ipProtoUDP, src: srcB, dst: dst, payload: udpSegment(53)}))
	runProgram(t, prog, ipv4Packet(ipv4Options{protocol: ipProtoUDP, src: srcB, dst: dst, payload: udpSegment(53)}))

	records, err := readTraffic(m)
	if err != nil {
		t.Fatalf("readTraffic: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(records), records)
	}
	// readTraffic sorts by source IP, so 10.0.0.1 (srcB) must come first.
	if records[0].SourceIP != "10.0.0.1" || records[0].Protocol != "udp" || records[0].DestinationPort != 53 || records[0].Packets != 2 {
		t.Errorf("records[0] = %+v, want source 10.0.0.1 udp/53 packets=2", records[0])
	}
	if records[1].SourceIP != "10.0.0.9" || records[1].Protocol != "tcp" || records[1].DestinationPort != 443 || records[1].Packets != 1 {
		t.Errorf("records[1] = %+v, want source 10.0.0.9 tcp/443 packets=1", records[1])
	}
}

// TestMapEvictionUnderLoad drives more distinct flows through the program
// than the map's max_entries, and asserts two things that matter for
// unbounded userspace/kernel memory growth: the program never errors or
// gets verifier-rejected while doing so, and the map never grows past its
// configured capacity, because LRU_HASH evicts rather than fails once full.
func TestMapEvictionUnderLoad(t *testing.T) {
	prog, m := loadIngressProgram(t)
	const maxEntries = 4096
	const distinctFlows = maxEntries + 1000

	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	for port := 0; port < distinctFlows; port++ {
		packet := ipv4Packet(ipv4Options{protocol: ipProtoTCP, src: src, dst: dst, payload: tcpSegment(uint16(port))})
		if ret := runProgram(t, prog, packet); ret != tcActOK {
			t.Fatalf("program returned %d on flow %d, want TC_ACT_OK", ret, port)
		}
	}

	if n := mapEntryCount(t, m); n > maxEntries {
		t.Fatalf("map has %d entries after %d distinct flows, want <= %d (max_entries)", n, distinctFlows, maxEntries)
	}
}
