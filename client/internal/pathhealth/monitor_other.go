//go:build !windows

package pathhealth

// StubMonitor provides a fallback implementation for non-Windows platforms.
type StubMonitor struct{}

// NewMonitor returns a new StubMonitor instance.
func NewMonitor() Monitor {
	return &StubMonitor{}
}

// CheckAll returns healthy mock states on non-Windows platforms.
func (m *StubMonitor) CheckAll(targets []MonitoredTarget) (map[uint32]InterfaceState, error) {
	results := make(map[uint32]InterfaceState)
	for _, t := range targets {
		results[t.IfIndex] = InterfaceState{
			IfIndex:    t.IfIndex,
			Name:       t.Name,
			IsUp:       true,
			HasIPv4:    true,
			HasGateway: true,
			Reason:     "non-windows mock",
		}
	}
	return results, nil
}
