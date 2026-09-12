//go:build linux

package main

import (
	"net"
	"os"
	"strconv"
	"time"
)

// notifySystemd sends a state string to the socket named by $NOTIFY_SOCKET,
// implementing the minimal sd_notify(3) protocol systemd's Type=notify
// services use. It is a no-op (returns nil) when NOTIFY_SOCKET is unset,
// which is the normal case outside of systemd (a terminal, CI, a plain
// `docker run`), so this never affects non-systemd usage.
func notifySystemd(state string) error {
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath == "" {
		return nil
	}
	addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// watchdogInterval returns how often GhostPort should send "WATCHDOG=1",
// derived from $WATCHDOG_USEC the way sd_watchdog_enabled(3) specifies:
// systemd sets it only when the unit configures WatchdogSec=, and this
// process should ping at less than half that interval. Returns 0 if no
// watchdog is configured, which the caller treats as "don't ping".
func watchdogInterval() time.Duration {
	usec := os.Getenv("WATCHDOG_USEC")
	if usec == "" {
		return 0
	}
	n, err := strconv.ParseInt(usec, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Microsecond / 2
}
