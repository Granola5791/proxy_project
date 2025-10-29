package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Address struct {
	Mac  string
	Ip   string
	Port int
}

var clientAddress Address

func HandleClientConnection() {
	var packetType string
	handle, err := pcap.OpenLive(
		GetStringFromConfig("network_device"),
		int32(GetIntFromConfig("pcap_snaplen")),
		GetBoolFromConfig("pcap_promiscuous"),
		pcap.BlockForever,
	)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.SetBPFFilter("dst port " + GetStringFromConfig("proxy_client_port"))
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	fmt.Println("listening on " + "dst port " + GetStringFromConfig("proxy_client_port"))

	// Create packet source
	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	// Listen for packets
	fmt.Println("Listening for packets...")
	for packet := range packets.Packets() {

		// start log----------------------------------------
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.SYN && !tcp.ACK {
				packetType = "SYN"
			} else if tcp.SYN && tcp.ACK {
				packetType = "SYN-ACK"
			} else if tcp.FIN && tcp.ACK {
				packetType = "FIN-ACK"
			} else if tcp.FIN && !tcp.ACK {
				packetType = "FIN"
			} else if tcp.ACK && !tcp.SYN && !tcp.FIN {
				packetType = "ACK"
			} else if tcp.RST {
				packetType = "RST"
			} else {
				packetType = "OTHER"
			}
		} else {
			packetType = "UNKNOWN"
		}

		fmt.Println("from client received: " + packetType)
		fmt.Println("to server sending" + packetType)
		// end log------------------------------------------

		// Extract layers
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer = packet.Layer(layers.LayerTypeTCP)

		if ethLayer == nil || ipLayer == nil || tcpLayer == nil {
			fmt.Println("Packet does not contain required layers")
			return
		}

		// Cast layers to their respective types
		eth := ethLayer.(*layers.Ethernet)
		ip := ipLayer.(*layers.IPv4)
		tcp := tcpLayer.(*layers.TCP)

		clientAddress = Address{
			Mac:  eth.SrcMAC.String(),
			Ip:   ip.SrcIP.String(),
			Port: int(tcp.SrcPort),
		}

		ForwardPacket(
			packet,
			handle,
			Address{
				Mac:  GetStringFromConfig("server_mac"),
				Ip:   GetStringFromConfig("server_ip"),
				Port: GetIntFromConfig("server_port"),
			},
			Address{
				Mac:  GetStringFromConfig("proxy_mac"),
				Ip:   GetStringFromConfig("proxy_ip"),
				Port: GetIntFromConfig("proxy_server_port"),
			},
		)
	}
}

func HandleServerConnection() {
	var packetType string
	handle, err := pcap.OpenLive(
		GetStringFromConfig("network_device"),
		int32(GetIntFromConfig("pcap_snaplen")),
		GetBoolFromConfig("pcap_promiscuous"),
		pcap.BlockForever,
	)
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter("dst port " + GetStringFromConfig("proxy_server_port"))
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	fmt.Println("listening on " + "dst port " + GetStringFromConfig("proxy_server_port"))

	// Create packet source
	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	// Listen for packets
	fmt.Println("Listening for server packets...")
	for packet := range packets.Packets() {
		// start log----------------------------------------
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.SYN && !tcp.ACK {
				packetType = "SYN"
			} else if tcp.SYN && tcp.ACK {
				packetType = "SYN-ACK"
			} else if tcp.FIN && tcp.ACK {
				packetType = "FIN-ACK"
			} else if tcp.FIN && !tcp.ACK {
				packetType = "FIN"
			} else if tcp.ACK && !tcp.SYN && !tcp.FIN {
				packetType = "ACK"
			} else if tcp.RST {
				packetType = "RST"
			} else {
				packetType = "OTHER"
			}
		} else {
			packetType = "UNKNOWN"
		}

		fmt.Println("to client sending" + packetType)
		fmt.Println("from server received: " + packetType)
		// end log------------------------------------------
		ForwardPacket(
			packet,
			handle,
			clientAddress,
			Address{
				Mac:  GetStringFromConfig("proxy_mac"),
				Ip:   GetStringFromConfig("proxy_ip"),
				Port: GetIntFromConfig("proxy_client_port"),
			},
		)
	}
}