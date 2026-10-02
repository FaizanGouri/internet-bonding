package main

import (
	"fmt"
	"os"

	"internet-bonding/client/internal/adapter"
	"internet-bonding/client/internal/monitor"
)

func main() {
	fmt.Println("==================================================")
	fmt.Println("     True Internet Bonding: Path Monitoring (CLI) ")
	fmt.Println("==================================================")
	fmt.Println()

	// 1. Discover physical adapters using Phase 1 adapter package
	discoverer := adapter.NewDiscoverer()
	res, err := discoverer.Discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Adapter discovery failed: %v\n", err)
		os.Exit(1)
	}

	if len(res.Physical) == 0 {
		fmt.Println("No physical bonding interfaces found.")
		return
	}

	// 2. Initialize Windows-native interface-bound ICMP prober
	prober, err := monitor.NewWindowsICMPProber()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize Windows ICMP prober: %v\n", err)
		os.Exit(1)
	}

	mon := monitor.NewMonitor(prober, monitor.DefaultConfig())

	// 3. Monitor each physical path independently
	for i, iface := range res.Physical {
		pathState := mon.CheckPath(iface)
		fmt.Println(pathState.String())
		if i < len(res.Physical)-1 {
			fmt.Println()
		}
	}
}
