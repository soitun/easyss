//go:build !darwin

package main

import (
	"fmt"
	"os"
)

// Stubs for darwin-only TUN helper functions.
// These are never called on non-darwin (runtime.GOOS guards in tray.go),
// but must exist for compilation.

func runTunHelper(_ int, _, _, _, _, _, _, _, _ string) {
	fmt.Fprintln(os.Stderr, "tun-helper is only supported on macOS")
	os.Exit(1)
}

func parseTunHelperArgs() (int, string, string, string, string, string, string, string, string) {
	return 0, "", "", "", "", "", "", "", ""
}

func (a *TrayApp) launchTunHelper() (int, string, error) {
	return 0, "", fmt.Errorf("tun helper not supported on this platform")
}

func (a *TrayApp) createTun2socksWithFD(_ int, _ string) {}

func (a *TrayApp) closeTunRoutesAndDNS() error {
	return nil
}
