package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"internet-bonding/protocol"
	"internet-bonding/server/internal/session"
	"internet-bonding/server/internal/tun"
)

func configureLinuxNetworking(tunDevName, natDev string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// 1. Enable IPv4 forwarding
	if out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		log.Printf("[WARN] Failed to set net.ipv4.ip_forward=1: %s (%v)", string(out), err)
	} else {
		log.Println("[ROUTING] IPv4 forwarding enabled")
	}

	// 2. Configure NAT / MASQUERADE on egress interface
	checkNat := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-o", natDev, "-j", "MASQUERADE")
	if checkNat.Run() != nil {
		addNat := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", natDev, "-j", "MASQUERADE")
		if out, err := addNat.CombinedOutput(); err != nil {
			log.Printf("[WARN] Failed to add iptables MASQUERADE: %s (%v)", string(out), err)
		} else {
			log.Printf("[ROUTING] iptables MASQUERADE configured on %s", natDev)
		}
	} else {
		log.Printf("[ROUTING] iptables MASQUERADE already present on %s", natDev)
	}

	// 3. Configure TCP MSS Clamping to prevent MTU black-holes
	clampCmd := exec.Command("iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	_ = clampCmd.Run()

	return nil
}

func main() {
	port := flag.Int("port", 51820, "UDP port to listen on")
	bindIP := flag.String("bind", "0.0.0.0", "IP address to bind UDP listener")
	pskHex := flag.String("psk", "", "Hex-encoded 32-byte Pre-Shared Key (or set BONDING_PSK env)")
	enableTun := flag.Bool("tun", true, "Enable real Linux TUN virtual interface")
	tunName := flag.String("tun-name", "tun0", "Name of the Linux TUN interface")
	tunIP := flag.String("tun-ip", "10.8.0.1/24", "IPv4 address and subnet for TUN interface")
	tunMTU := flag.Int("tun-mtu", 1400, "MTU for TUN interface")
	natDev := flag.String("nat-dev", "eth0", "Egress physical interface for NAT masquerade")
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

	// Initialize Linux TUN device if enabled and on Linux
	var tunDevice tun.Device
	if *enableTun && runtime.GOOS == "linux" {
		tunDev, err := tun.OpenTun(*tunName, *tunIP, *tunMTU)
		if err != nil {
			log.Printf("[WARN] Failed to open Linux TUN device (%s): %v. Running in UDP-only mode.", *tunName, err)
		} else {
			tunDevice = tunDev
			defer tunDevice.Close()
			fmt.Printf("TUN Interface: %s assigned %s (MTU: %d)\n", tunDevice.Name(), *tunIP, *tunMTU)
			_ = configureLinuxNetworking(tunDevice.Name(), *natDev)
		}
	} else if runtime.GOOS != "linux" {
		fmt.Println("TUN Interface: Skipped (non-Linux platform)")
	}

	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down UDP tunnel server gracefully...")
		if tunDevice != nil {
			_ = tunDevice.Close()
		}
		conn.Close()
		os.Exit(0)
	}()

	// TUN Reader Loop: Reads IP packets from TUN and transmits down to client via UDP
	if tunDevice != nil {
		go func() {
			tunBuf := make([]byte, 2048)
			for {
				n, err := tunDevice.Read(tunBuf)
				if err != nil {
					return
				}
				if n < 20 {
					continue
				}

				// Verify IPv4
				if (tunBuf[0] >> 4) != 4 {
					continue
				}

				dstIP := net.IP(tunBuf[16:20])

				sess, err := sessionTable.GetSessionByVirtualIP(dstIP)
				if err != nil {
					log.Printf("[TUN ROUTE DROP] No session for dest %s: %v", dstIP.String(), err)
					continue
				}

				pathID, clientEndpoint, err := sessionTable.SelectDownstreamPath(sess.SessionID)
				if err != nil || clientEndpoint == nil {
					log.Printf("[TUN ROUTE DROP] No active path for session %016X: %v", sess.SessionID, err)
					continue
				}

				seq := sessionTable.NextDownstreamSeq(sess.SessionID)
				dataPkt := protocol.NewDataPacket(sess.SessionID, pathID, seq, tunBuf[:n], psk)
				raw, err := dataPkt.MarshalBinary()
				if err != nil {
					log.Printf("[ERROR] Failed to marshal DATA packet for client: %v", err)
					continue
				}

				_, err = conn.WriteToUDP(raw, clientEndpoint)
				if err != nil {
					log.Printf("[TUN WRITE ERROR] Failed to send to %s: %v", clientEndpoint, err)
				} else {
					sessionTable.RecordDownstreamTx(sess.SessionID, pathID, n)
					if seq <= 10 || seq%25 == 0 {
						fmt.Printf("[%s] DATA Out: to Client %s (Path %d) Seq=%-5d Size=%-4d\n",
							time.Now().Format("15:04:05.000"), clientEndpoint.String(), pathID, seq, n)
					}
				}
			}
		}()

		// Reorder Gap Flush Loop: Flushes expired out-of-order packets from reorder buffer to Linux TUN
		go func() {
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-sigChan:
					return
				case <-ticker.C:
					flushed := sessionTable.CheckAllReorderTimeouts()
					for _, ipPkt := range flushed {
						_, _ = tunDevice.Write(ipPkt)
					}
				}
			}
		}()
	}

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

		// Handle Version 2 (Phase 3B Multi-Path & Phase 3C Data)
		if pkt.Version == protocol.ProtocolVersion2 {
			resp, ipPackets, err := sessionTable.ProcessIncomingPacket(&pkt, clientAddr, psk)
			if err != nil {
				log.Printf("[SECURITY DROP] Failed authentication from %s: %v (Total drops: %d)",
					clientAddr, err, sessionTable.SecurityDropCount())
				continue
			}

			// Forward extracted in-order IP packets to Linux TUN device
			if len(ipPackets) > 0 && tunDevice != nil {
				for _, ipPkt := range ipPackets {
					_, _ = tunDevice.Write(ipPkt)
				}
			}

			// If control response is generated (e.g. KeepaliveAck or Echo)
			if resp != nil {
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
			}

			if pkt.Type == protocol.PacketTypeData {
				// Log periodically or on data arrival
				if pkt.SeqNum%25 == 0 || pkt.SeqNum <= 5 {
					fmt.Printf("[%s] DATA In: Session=%016X Path=%d Seq=%-5d Size=%-4d Client=%-21s | DeliveredToTUN=%d\n",
						time.Now().Format("15:04:05.000"),
						pkt.SessionID,
						pkt.PathID,
						pkt.SeqNum,
						len(pkt.Payload),
						clientAddr.String(),
						len(ipPackets),
					)
				}
			} else {
				fmt.Printf("[%s] V2 Control: Session=%016X Path=%d Seq=%-4d Client=%-21s | Drops: %d | Total: %d\n",
					time.Now().Format("15:04:05.000"),
					pkt.SessionID,
					pkt.PathID,
					pkt.SeqNum,
					clientAddr.String(),
					sessionTable.SecurityDropCount(),
					totalPackets,
				)
			}
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
