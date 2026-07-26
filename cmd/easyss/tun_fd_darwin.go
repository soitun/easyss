//go:build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

// launchTunHelper creates a Unix socket pair, launches a one-shot root helper
// via osascript, and receives the TUN file descriptor and device name.
func (a *TrayApp) launchTunHelper() (fd int, devName string, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, "", fmt.Errorf("socketpair: %w", err)
	}
	parentFD := fds[0]
	childFD := fds[1]
	defer unix.Close(parentFD) //nolint:errcheck

	args := []string{
		"-tun-helper",
		"-tun-fd", fmt.Sprintf("%d", childFD),
		"-tun-ip", "198.18.0.1",
		"-tun-gw", "198.18.0.1",
		"-tun-local-gw", a.tunLocalGateway(),
	}
	if v6 := a.tunServerIPV6(); v6 != "" {
		args = append(args,
			"-tun-ipv6-sub", "2001:0db8:0:f101::1",
			"-tun-gw-v6", "fe80::30ff:1eff:feff:aaff",
			"-tun-server-ipv6", v6,
			"-tun-local-gw-v6", a.tunLocalGatewayV6(),
		)
	}
	args = append(args, "-tun-dns", config.DefaultSystemDNS)

	if err := execElevated(args...); err != nil {
		unix.Close(childFD) //nolint:errcheck //nolint:errcheck
		return 0, "", fmt.Errorf("launch helper: %w", err)
	}
	unix.Close(childFD) //nolint:errcheck

	fd, name, err := receiveFD(parentFD)
	if err != nil {
		return 0, "", fmt.Errorf("receive fd: %w", err)
	}

	return fd, name, nil
}

// execElevated runs the current binary as root via osascript with the given args.
func execElevated(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(exe, "'", "'\\''")))
	for _, a := range args {
		b.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(a, "'", "'\\''")))
	}
	cmdStr := fmt.Sprintf("'%s' %s &>/dev/null &", exe, b.String())
	scriptCmd := strings.ReplaceAll(cmdStr, "\"", "\\\"")
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)
	_, err = util.Command("osascript", "-e", script)
	return err
}

// receiveFD receives a file descriptor via SCM_RIGHTS from a Unix socket.
func receiveFD(fd int) (int, string, error) {
	conn, err := net.FileConn(os.NewFile(uintptr(fd), "tun-parent"))
	if err != nil {
		return 0, "", err
	}
	defer conn.Close() //nolint:errcheck

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, "", fmt.Errorf("not a unix connection")
	}

	oob := make([]byte, unix.CmsgSpace(4))
	data := make([]byte, 256)
	n, oobn, _, _, err := unixConn.ReadMsgUnix(data, oob)
	if err != nil {
		return 0, "", err
	}

	name := strings.TrimSpace(string(data[:n]))
	if strings.HasPrefix(name, "ERR:") {
		return 0, "", fmt.Errorf("helper error: %s", name[4:])
	}

	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(scms) < 1 {
		return 0, "", fmt.Errorf("parse control message: %w", err)
	}

	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil || len(fds) < 1 {
		return 0, "", fmt.Errorf("parse unix rights: %w", err)
	}

	return fds[0], name, nil
}

// closeTunRoutesAndDNS runs the teardown script via osascript to remove routes
// and restore DNS after stopping TUN in fd mode.
func (a *TrayApp) closeTunRoutesAndDNS() error {
	defer a.restoreDNSViaOSAScript() //nolint:errcheck
	return a.runCloseScriptViaOSAScript()
}

// runCloseScriptViaOSAScript runs the TUN teardown script as root via osascript.
func (a *TrayApp) runCloseScriptViaOSAScript() error {
	if scripts.CloseTunBytes == nil {
		return nil
	}
	namePath, err := util.WriteToTemp(scripts.CloseTunFilename, scripts.CloseTunBytes)
	if err != nil {
		return err
	}
	defer os.RemoveAll(namePath) //nolint:errcheck

	device := "utun9"
	cmd := fmt.Sprintf("do shell script \"sh %s %s\" with administrator privileges",
		strings.ReplaceAll(namePath, "\"", "\\\""),
		device)
	_, err = util.Command("osascript", "-e", cmd)
	return err
}

// restoreDNSViaOSAScript restores DNS to empty (DHCP) via osascript.
func (a *TrayApp) restoreDNSViaOSAScript() error {
	ni, err := util.NetworkInterface()
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("do shell script \"networksetup -setdnsservers %s empty\" with administrator privileges", ni)
	_, err = util.Command("osascript", "-e", cmd)
	return err
}

// createTun2socksWithFD starts TUN mode using a pre-created file descriptor
// obtained from the privileged helper.
func (a *TrayApp) createTun2socksWithFD(tunFD int, deviceName string) {
	if a.tunMgr != nil {
		return
	}
	a.cfg.Local.EnableTun2socks = true
	a.tunMgr = tun.New(tun.Config{
		Socks5Addr: fmt.Sprintf("socks5://127.0.0.1:%d", a.cfg.Local.SocksPort),
	})

	if a.core != nil && a.core.Client != nil {
		icmpHandler := tun.NewICMPHandler(a.core.Client.Router())
		icmpHandler.SetProxy(a.core.StreamHandler, methodFromString(a.cfg.DefaultServer().Method))
		go func() {
			if err := a.tunMgr.StartWithFD(tunFD, deviceName, icmpHandler); err != nil {
				log.Error("[SYSTRAY] tun2socks start (fd)", "err", err)
			}
		}()
	}
}

func (a *TrayApp) tunLocalGateway() string {
	gw, _, _ := util.SysGatewayAndDevice()
	return gw
}

func (a *TrayApp) tunLocalGatewayV6() string {
	gw, _, _ := util.SysGatewayAndDeviceV6()
	return gw
}

func (a *TrayApp) tunServerIPV6() string {
	if a.core != nil && a.core.Client != nil {
		return a.core.Client.Router().ServerIPV6()
	}
	return ""
}
