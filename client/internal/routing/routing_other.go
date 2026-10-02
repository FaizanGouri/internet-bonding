//go:build !windows

package routing

type DummyRouteManager struct{}

func NewRouteManager() *DummyRouteManager {
	return &DummyRouteManager{}
}

func (d *DummyRouteManager) AddRoute(prefix string, ifIndex uint32, gateway string, metric int) error {
	return nil
}

func (d *DummyRouteManager) Cleanup() {}
