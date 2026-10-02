//go:build windows

package routing

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
)

type installedRoute struct {
	prefix  string
	ifIndex uint32
	gateway string
}

// WindowsRouteManager dynamically tracks and rolls back installed routes.
type WindowsRouteManager struct {
	mu     sync.Mutex
	routes []installedRoute
}

func NewRouteManager() *WindowsRouteManager {
	return &WindowsRouteManager{}
}

// AddRoute installs an IPv4 route via netsh and registers it for cleanup.
func (rm *WindowsRouteManager) AddRoute(prefix string, ifIndex uint32, gateway string, metric int) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	args := []string{"interface", "ipv4", "add", "route", prefix, fmt.Sprintf("%d", ifIndex)}
	if gateway != "" {
		args = append(args, gateway)
	}
	if metric > 0 {
		args = append(args, fmt.Sprintf("metric=%d", metric))
	}
	args = append(args, "store=active")

	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add route %s via %d/%s: %s (%w)", prefix, ifIndex, gateway, string(out), err)
	}

	rm.routes = append(rm.routes, installedRoute{
		prefix:  prefix,
		ifIndex: ifIndex,
		gateway: gateway,
	})
	return nil
}

// Cleanup removes all routes installed by this manager.
func (rm *WindowsRouteManager) Cleanup() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i := len(rm.routes) - 1; i >= 0; i-- {
		r := rm.routes[i]
		args := []string{"interface", "ipv4", "delete", "route", r.prefix, fmt.Sprintf("%d", r.ifIndex)}
		if r.gateway != "" {
			args = append(args, r.gateway)
		}
		cmd := exec.Command("netsh", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run()
	}
	rm.routes = nil
}
