//go:build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
	tun "golang.zx2c4.com/wireguard/tun"
)

// runTunHelper creates a TUN device as root, passes the file descriptor and
// device name to the parent process via a Unix domain socket (SCM_RIGHTS),
// configures the interface / routes / DNS, then exits. This is a one-shot
// privileged helper called by the non-root tray process on macOS.
func runTunHelper(connFD int, tunIP, tunGW, localGateway, tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6, dnsServer string) {
	conn := os.NewFile(uintptr(connFD), "tun-helper-conn")
	defer conn.Close() //nolint:errcheck

	// Create TUN device.
	dev, err := tun.CreateTUN("utun", 1500)
	if err != nil {
		sendError(conn, fmt.Errorf("create tun: %w", err))
		return
	}

	name, err := dev.Name()
	if err != nil {
		sendError(conn, fmt.Errorf("tun name: %w", err))
		return
	}

	// Send fd and device name to parent.
	tunFile := dev.File()
	rawFD := int(tunFile.Fd())
	if err := sendFD(conn, rawFD, name); err != nil {
		sendError(conn, fmt.Errorf("send fd: %w", err))
		return
	}

	// Close our copy of the TUN fd — the parent now owns it.
	dev.Close() //nolint:errcheck

	// Configure interface, routes and DNS.
	if err := configureTun(name, tunIP, tunGW, localGateway, tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6); err != nil {
		log.Warn("[TUN-HELPER] configure tun", "err", err)
	}

	if dnsServer != "" {
		if err := setDNS(name, dnsServer); err != nil {
			log.Warn("[TUN-HELPER] set dns", "err", err)
		}
	}

	log.Info("[TUN-HELPER] tun device ready", "name", name)
}

func sendFD(conn *os.File, fd int, name string) error {
	uc, err := net.FileConn(conn)
	if err != nil {
		return err
	}
	defer uc.Close() //nolint:errcheck
	unixConn, ok := uc.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	oob := unix.UnixRights(fd)
	_, _, err = unixConn.WriteMsgUnix([]byte(name+"\n"), oob, nil)
	return err
}

func sendError(conn *os.File, err error) {
	_, _ = conn.Write([]byte("ERR:" + err.Error() + "\n"))
}

func configureTun(name, tunIP, tunGW, localGateway, tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6 string) error {
	if scripts.CreateTunBytes == nil {
		return fmt.Errorf("no create tun script")
	}

	namePath, err := util.WriteToTemp("create_tun.sh", scripts.CreateTunBytes)
	if err != nil {
		return err
	}
	defer os.RemoveAll(namePath) //nolint:errcheck

	output, err := exec.Command("sh", namePath, name, tunIP, tunGW, localGateway,
		tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6).CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure tun: %w: %s", err, output)
	}
	return nil
}

func setDNS(iface, dnsServer string) error {
	ni, err := util.NetworkInterface()
	if err != nil {
		return fmt.Errorf("get network interface: %w", err)
	}
	_, err = exec.Command("networksetup", "-setdnsservers", ni, dnsServer).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set dns: %w", err)
	}
	_ = iface
	_ = dnsServer
	return nil
}

// parseTunHelperArgs parses command-line arguments for tun-helper mode.
// Expected: -tun-fd <fd> -tun-ip ... -tun-gw ... -tun-local-gw ... etc.
func parseTunHelperArgs() (connFD int, tunIP, tunGW, localGateway, tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6, dnsServer string) {
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-tun-fd":
			i++
			connFD, _ = strconv.Atoi(args[i])
		case "-tun-ip":
			i++
			tunIP = args[i]
		case "-tun-gw":
			i++
			tunGW = args[i]
		case "-tun-local-gw":
			i++
			localGateway = args[i]
		case "-tun-ipv6-sub":
			i++
			tunIPV6Sub = args[i]
		case "-tun-gw-v6":
			i++
			tunGWV6 = args[i]
		case "-tun-server-ipv6":
			i++
			serverIPV6 = args[i]
		case "-tun-local-gw-v6":
			i++
			localGatewayV6 = args[i]
		case "-tun-dns":
			i++
			dnsServer = args[i]
		}
	}
	return
}
