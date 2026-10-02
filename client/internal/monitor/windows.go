//go:build windows

package monitor

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// icmpEchoReply mirrors the Win32 ICMP_ECHO_REPLY structure.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       [8]byte
}

// WindowsICMPProber executes interface-bound ICMP echo requests using Win32 IcmpSendEcho2Ex.
type WindowsICMPProber struct {
	dll                 *syscall.LazyDLL
	procIcmpCreateFile  *syscall.LazyProc
	procIcmpCloseHandle *syscall.LazyProc
	procIcmpSendEcho2Ex *syscall.LazyProc
}

// NewWindowsICMPProber initializes the Windows IP Helper ICMP handle and API pointers.
func NewWindowsICMPProber() (*WindowsICMPProber, error) {
	dll := syscall.NewLazyDLL("iphlpapi.dll")
	pCreate := dll.NewProc("IcmpCreateFile")
	pClose := dll.NewProc("IcmpCloseHandle")
	pSend := dll.NewProc("IcmpSendEcho2Ex")

	if err := pCreate.Find(); err != nil {
		return nil, fmt.Errorf("IcmpCreateFile symbol not found in iphlpapi.dll: %w", err)
	}
	if err := pClose.Find(); err != nil {
		return nil, fmt.Errorf("IcmpCloseHandle symbol not found in iphlpapi.dll: %w", err)
	}
	if err := pSend.Find(); err != nil {
		return nil, fmt.Errorf("IcmpSendEcho2Ex symbol not found in iphlpapi.dll: %w", err)
	}

	return &WindowsICMPProber{
		dll:                 dll,
		procIcmpCreateFile:  pCreate,
		procIcmpCloseHandle: pClose,
		procIcmpSendEcho2Ex: pSend,
	}, nil
}

// Probe sends a single ICMP echo request bound strictly to srcIP.
func (p *WindowsICMPProber) Probe(srcIP, dstIP net.IP, timeout time.Duration) ProbeResult {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return ProbeResult{Success: false, Err: fmt.Errorf("invalid IPv4 address")}
	}

	h, _, err := p.procIcmpCreateFile.Call()
	if h == uintptr(syscall.InvalidHandle) {
		return ProbeResult{Success: false, Err: fmt.Errorf("IcmpCreateFile failed: %w", err)}
	}
	defer p.procIcmpCloseHandle.Call(h)

	srcAddr := binary.LittleEndian.Uint32(src4)
	dstAddr := binary.LittleEndian.Uint32(dst4)

	reqData := []byte("AntigravityBondingHealthProbePing123")
	replyBuf := make([]byte, 1024)

	timeoutMs := uint32(timeout.Milliseconds())
	if timeoutMs == 0 {
		timeoutMs = 1000
	}

	ret, _, err := p.procIcmpSendEcho2Ex.Call(
		h,
		0,
		0,
		0,
		uintptr(srcAddr),
		uintptr(dstAddr),
		uintptr(unsafe.Pointer(&reqData[0])),
		uintptr(len(reqData)),
		0,
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(len(replyBuf)),
		uintptr(timeoutMs),
	)

	if ret == 0 {
		return ProbeResult{Success: false, Err: err}
	}

	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != 0 {
		return ProbeResult{Success: false, Err: fmt.Errorf("ICMP error status: %d", reply.Status)}
	}

	rtt := time.Duration(reply.RoundTripTime) * time.Millisecond

	return ProbeResult{
		Success: true,
		RTT:     rtt,
	}
}
