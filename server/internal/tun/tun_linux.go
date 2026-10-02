//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ifreq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

type LinuxTun struct {
	file *os.File
	name string
}

func OpenTun(name string, ipCIDR string, mtu int) (*LinuxTun, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	var req ifreq
	req.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	copy(req.Name[:], name)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		file.Fd(),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %w", errno)
	}

	actualName := unix.ByteSliceToString(req.Name[:])

	// Configure IP and MTU via ip link/addr commands
	if ipCIDR != "" {
		_ = exec.Command("ip", "addr", "add", ipCIDR, "dev", actualName).Run()
	}

	if mtu > 0 {
		out, err := exec.Command("ip", "link", "set", "dev", actualName, "mtu", fmt.Sprintf("%d", mtu), "up").CombinedOutput()
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to set mtu and bring up %s: %s (%w)", actualName, string(out), err)
		}
	} else {
		out, err := exec.Command("ip", "link", "set", "dev", actualName, "up").CombinedOutput()
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to bring up %s: %s (%w)", actualName, string(out), err)
		}
	}

	return &LinuxTun{
		file: file,
		name: actualName,
	}, nil
}

func (t *LinuxTun) Read(b []byte) (int, error) {
	return t.file.Read(b)
}

func (t *LinuxTun) Write(b []byte) (int, error) {
	return t.file.Write(b)
}

func (t *LinuxTun) Close() error {
	return t.file.Close()
}

func (t *LinuxTun) Name() string {
	return t.name
}
