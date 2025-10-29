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

func GetSrcAddressTCP(packet gopacket.Packet) Address {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ethLayer != nil && ipLayer != nil && tcpLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		ip := ipLayer.(*layers.IPv4)
		tcp := tcpLayer.(*layers.TCP)
		return Address{eth.SrcMAC.String(), ip.SrcIP.String(), int(tcp.SrcPort)}
	}
	return Address{"", "", 0}
}

func GetSrcAddressUDP(packet gopacket.Packet) Address {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ethLayer != nil && ipLayer != nil && udpLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		ip := ipLayer.(*layers.IPv4)
		udp := udpLayer.(*layers.UDP)
		return Address{eth.SrcMAC.String(), ip.SrcIP.String(), int(udp.SrcPort)}
	}
	return Address{"", "", 0}
}

func IsUDP(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeUDP) != nil
}

func IsTCP(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeTCP) != nil
}

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

		if IsTCP(packet) {
			clientAddress = GetSrcAddressTCP(packet)

			ForwardTCPPacket(
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
		} else if IsUDP(packet) {
			clientAddress = GetSrcAddressUDP(packet)

			ForwardUDPPacket(
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
		} else {
			fmt.Println("Packet does not contain required layers")
			return
		}
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

		if IsTCP(packet) {
			ForwardTCPPacket(
				packet,
				handle,
				clientAddress,
				Address{
					Mac:  GetStringFromConfig("proxy_mac"),
					Ip:   GetStringFromConfig("proxy_ip"),
					Port: GetIntFromConfig("proxy_client_port"),
				},
			)
		} else if IsUDP(packet) {
			ForwardUDPPacket(
				packet,
				handle,
				clientAddress,
				Address{
					Mac:  GetStringFromConfig("proxy_mac"),
					Ip:   GetStringFromConfig("proxy_ip"),
					Port: GetIntFromConfig("proxy_client_port"),
				},
			)
		} else {
			fmt.Println("Packet does not contain required layers")
			return
		}
	}
}
