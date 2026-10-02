package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"internet-bonding/protocol"
	"internet-bonding/server/internal/session"
)

func main() {
	port := flag.Int("port", 51820, "UDP port to listen on")
	bindIP := flag.String("bind", "0.0.0.0", "IP address to bind UDP listener")
	pskHex := flag.String("psk", "", "Hex-encoded 32-byte Pre-Shared Key (or set BONDING_PSK env)")
	flag.Parse()

	// Resolve PSK from flag or environment variable
	var psk []byte
	pskStr := *pskHex
	if pskStr == "" {
		pskStr = os.Getenv("BONDING_PSK")
	}

	if pskStr != "" {
		decoded, err := hex.DecodeString(pskStr)
		if err != nil || len(decoded) != 32 {
			log.Fatalf("Invalid PSK: must be a 64-character hex string (32 bytes)")
		}
		psk = decoded
	}

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

	sessionTable := session.NewSessionTable()

	fmt.Println("==================================================")
	fmt.Println("     True Internet Bonding: VPS Tunnel Server     ")
	fmt.Println("==================================================")
	fmt.Printf("Listening for UDP tunnel packets on %s\n", addrStr)
	if len(psk) > 0 {
		fmt.Println("Security: HMAC-SHA256 authentication enabled (PSK loaded)")
	} else {
		fmt.Println("Security: Running in compatibility mode (no PSK configured)")
	}
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
			log.Printf("[DROP] Malformed packet from %s: %v", clientAddr, err)
			continue
		}

		totalPackets++
		transitTime := time.Since(pkt.Timestamp)

		// Handle Version 2 (Phase 3B Multi-Path with Session & HMAC)
		if pkt.Version == protocol.ProtocolVersion2 {
			resp, err := sessionTable.ProcessPacket(&pkt, clientAddr, psk)
			if err != nil {
				log.Printf("[SECURITY DROP] Failed authentication from %s: %v (Total drops: %d)",
					clientAddr, err, sessionTable.SecurityDropCount())
				continue
			}

			respBytes, err := resp.MarshalBinary()
			if err != nil {
				log.Printf("[ERROR] Failed to marshal V2 response: %v", err)
				continue
			}

			_, err = conn.WriteToUDP(respBytes, clientAddr)
			if err != nil {
				log.Printf("[ERROR] Failed to send V2 response to %s: %v", clientAddr, err)
				continue
			}

			fmt.Printf("[%s] V2 Resp: Session=%016X Path=%d Seq=%-4d Client=%-21s | Drops: %d | Total: %d\n",
				time.Now().Format("15:04:05.000"),
				pkt.SessionID,
				pkt.PathID,
				pkt.SeqNum,
				clientAddr.String(),
				sessionTable.SecurityDropCount(),
				totalPackets,
			)
			continue
		}

		// Handle Version 1 (Phase 3A Backward Compatibility)
		pkt.Type = protocol.PacketTypeEcho
		respBytes, err := pkt.MarshalBinary()
		if err != nil {
			log.Printf("[ERROR] Failed to marshal V1 echo for seq=%d: %v", pkt.SeqNum, err)
			continue
		}

		_, err = conn.WriteToUDP(respBytes, clientAddr)
		if err != nil {
			log.Printf("[ERROR] Failed to send V1 echo to %s: %v", clientAddr, err)
			continue
		}

		fmt.Printf("[%s] V1 Echo: Seq=%-4d to Client=%-21s | Payload=%-3d bytes | One-way: %s | Total: %d\n",
			time.Now().Format("15:04:05.000"),
			pkt.SeqNum,
			clientAddr.String(),
			len(pkt.Payload),
			transitTime.Round(time.Microsecond),
			totalPackets,
		)
	}
}
