package routing

// Manager tracks and cleans up dynamically installed network routes.
type Manager interface {
	Cleanup()
}
