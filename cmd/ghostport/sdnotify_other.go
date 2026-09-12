//go:build !linux

package main

import "time"

// notifySystemd is a no-op off Linux: there is no systemd to notify.
func notifySystemd(state string) error {
	return nil
}

// watchdogInterval is always "no watchdog" off Linux.
func watchdogInterval() time.Duration {
	return 0
}
