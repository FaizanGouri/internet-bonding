package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"internet-bonding/protocol"
)

func main() {
	port := flag.Int("port", 51820, "UDP port to listen on")
	bindIP := flag.String("bind", "0.0.0.0", "IP address to bind UDP listener")
	flag.Parse()

	addrStr := fmt.Sprintf("%s:%d", *bindIP, *port)
	addr, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		log.Fatalf("Failed to resolve bind address %s: %v", addrStr, err)
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Fatalf("Failed to start UDP listener on %s: %v", addrStr, err)
	}
	defer conn.Close()

	fmt.Println("==================================================")
	fmt.Println("     True Internet Bonding: VPS Tunnel Server     ")
	fmt.Println("==================================================")
	fmt.Printf("Listening for UDP tunnel packets on %s\n", addrStr)
	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down UDP tunnel server gracefully...")
		conn.Close()
		os.Exit(0)
	}()

	buf := make([]byte, 2048)
	var totalPackets uint64

	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Check if connection closed
			select {
			case <-sigChan:
				return
			default:
				log.Printf("Read error: %v", err)
				continue
			}
		}

		var pkt protocol.Packet
		if err := pkt.UnmarshalBinary(buf[:n]); err != nil {
			log.Printf("[DROP] Invalid packet from %s: %v", clientAddr, err)
			continue
		}

		totalPackets++
		transitTime := time.Since(pkt.Timestamp)

		// Echo packet back to client
		pkt.Type = protocol.PacketTypeEcho
		respBytes, err := pkt.MarshalBinary()
		if err != nil {
			log.Printf("[ERROR] Failed to marshal echo response for seq=%d: %v", pkt.SeqNum, err)
			continue
		}

		_, err = conn.WriteToUDP(respBytes, clientAddr)
		if err != nil {
			log.Printf("[ERROR] Failed to send echo to %s: %v", clientAddr, err)
			continue
		}

		fmt.Printf("[%s] Echoed Seq=%-4d to Client=%-21s | Payload=%-3d bytes | One-way: %s | Total: %d\n",
			time.Now().Format("15:04:05.000"),
			pkt.SeqNum,
			clientAddr.String(),
			len(pkt.Payload),
			transitTime.Round(time.Microsecond),
			totalPackets,
		)
	}
}
