package main

import (
	"fmt"
	"os"

	"internet-bonding/client/internal/adapter"
)

func main() {
	fmt.Println("==================================================")
	fmt.Println("   True Internet Bonding: Network Discovery (CLI) ")
	fmt.Println("==================================================")
	fmt.Println()

	discoverer := adapter.NewDiscoverer()
	result, err := discoverer.Discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during network discovery: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("--- Physical Bonding Candidates ---")
	if len(result.Physical) == 0 {
		fmt.Println("No physical Ethernet or Wi-Fi interfaces detected.")
	} else {
		for _, iface := range result.Physical {
			fmt.Println(iface.String())
			fmt.Println()
		}
	}

	fmt.Println("--- Filtered / Excluded Interfaces ---")
	if len(result.Filtered) == 0 {
		fmt.Println("No interfaces were filtered.")
	} else {
		for _, f := range result.Filtered {
			fmt.Println(f.String())
		}
	}
	fmt.Println()
}
