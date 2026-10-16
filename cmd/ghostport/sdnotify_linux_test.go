//go:build linux

package main

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestNotifySystemdSendsState(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "notify.sock")
	addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("listen on fake notify socket: %v", err)
	}
	defer listener.Close()

	t.Setenv("NOTIFY_SOCKET", socketPath)

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := listener.Read(buf)
		done <- string(buf[:n])
	}()

	if err := notifySystemd("READY=1"); err != nil {
		t.Fatalf("notifySystemd: %v", err)
	}

	select {
	case got := <-done:
		if got != "READY=1" {
			t.Fatalf("received %q, want %q", got, "READY=1")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive a datagram on the fake notify socket")
	}
}

func TestNotifySystemdNoopWithoutNotifySocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notifySystemd("READY=1"); err != nil {
		t.Fatalf("notifySystemd with no NOTIFY_SOCKET: %v", err)
	}
}

func TestWatchdogInterval(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("WATCHDOG_USEC", "")
		if got := watchdogInterval(); got != 0 {
			t.Fatalf("watchdogInterval() = %s, want 0", got)
		}
	})
	t.Run("30 seconds, halved", func(t *testing.T) {
		t.Setenv("WATCHDOG_USEC", "30000000")
		want := 15 * time.Second
		if got := watchdogInterval(); got != want {
			t.Fatalf("watchdogInterval() = %s, want %s", got, want)
		}
	})
	t.Run("invalid value", func(t *testing.T) {
		t.Setenv("WATCHDOG_USEC", "not-a-number")
		if got := watchdogInterval(); got != 0 {
			t.Fatalf("watchdogInterval() = %s, want 0", got)
		}
	})
}
