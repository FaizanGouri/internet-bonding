//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

var (
	modiphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceLuidToIndex = modiphlpapi.NewProc("ConvertInterfaceLuidToIndex")
)

type WindowsWintun struct {
	name      string
	adapter   *wintun.Adapter
	session   wintun.Session
	readEvent windows.Handle
	ifIndex   uint32
	closed    uint32
	closeOnce sync.Once
	closeChan chan struct{}
}

func convertLuidToIndex(luid uint64) (uint32, error) {
	var index uint32
	r1, _, err := procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
	if r1 != 0 {
		return 0, fmt.Errorf("ConvertInterfaceLuidToIndex failed (code %d): %w", r1, err)
	}
	return index, nil
}

// OpenWintun creates a Wintun virtual adapter, assigns its IP and MTU, and initializes ring buffers.
func OpenWintun(name string, ipStr string, maskStr string, mtu int) (*WindowsWintun, error) {
	guid, err := windows.GenerateGUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate adapter GUID: %w", err)
	}

	adapter, err := wintun.CreateAdapter(name, "Wintun", &guid)
	if err != nil {
		return nil, fmt.Errorf("failed to create Wintun adapter %q: %w", name, err)
	}

	luid := adapter.LUID()
	ifIndex, err := convertLuidToIndex(luid)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("failed to resolve interface index: %w", err)
	}

	// Configure IP via netsh
	if ipStr != "" && maskStr != "" {
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
			fmt.Sprintf("name=%s", name), "source=static",
			fmt.Sprintf("address=%s", ipStr), fmt.Sprintf("mask=%s", maskStr),
			"gateway=none",
		)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if out, err := cmd.CombinedOutput(); err != nil {
			adapter.Close()
			return nil, fmt.Errorf("failed to configure IP via netsh: %s (%w)", string(out), err)
		}
	}

	// Configure MTU via netsh
	if mtu > 0 {
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
			name, fmt.Sprintf("mtu=%d", mtu), "store=active",
		)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run()
	}

	// Start ring buffer session (8MB capacity)
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("failed to start Wintun session: %w", err)
	}

	return &WindowsWintun{
		name:      name,
		adapter:   adapter,
		session:   session,
		readEvent: session.ReadWaitEvent(),
		ifIndex:   ifIndex,
		closeChan: make(chan struct{}),
	}, nil
}

func (w *WindowsWintun) AdapterName() string {
	return w.name
}

func (w *WindowsWintun) IfIndex() uint32 {
	return w.ifIndex
}

func (w *WindowsWintun) Read(b []byte) (int, error) {
	for {
		if atomic.LoadUint32(&w.closed) == 1 {
			return 0, errors.New("wintun adapter closed")
		}

		packet, err := w.session.ReceivePacket()
		if err == nil {
			n := copy(b, packet)
			w.session.ReleaseReceivePacket(packet)
			return n, nil
		}

		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			// Wait for packet arrival or periodic wake-up
			eventWait, _ := windows.WaitForSingleObject(w.readEvent, 100)
			if eventWait == windows.WAIT_OBJECT_0 || eventWait == uint32(windows.WAIT_TIMEOUT) {
				continue
			}
		}

		return 0, err
	}
}

func (w *WindowsWintun) Write(b []byte) (int, error) {
	if atomic.LoadUint32(&w.closed) == 1 {
		return 0, errors.New("wintun adapter closed")
	}

	packet, err := w.session.AllocateSendPacket(len(b))
	if err != nil {
		return 0, fmt.Errorf("wintun AllocateSendPacket failed: %w", err)
	}

	copy(packet, b)
	w.session.SendPacket(packet)
	return len(b), nil
}

func (w *WindowsWintun) Close() error {
	var err error
	w.closeOnce.Do(func() {
		atomic.StoreUint32(&w.closed, 1)
		close(w.closeChan)
		w.session.End()
		err = w.adapter.Close()
	})
	return err
}
