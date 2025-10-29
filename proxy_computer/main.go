package main

import (
	"fmt"
	"log"
	"net"

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

func ForwardPacket(packet gopacket.Packet, handle *pcap.Handle, destAddress Address, proxyAddress Address) {
	var err error

	// Extract layers
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ethLayer == nil || ipLayer == nil || tcpLayer == nil {
		fmt.Println("Packet does not contain required layers")
		return
	}

	// Cast layers to their respective types
	eth := ethLayer.(*layers.Ethernet)
	ip := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)

	// Get the payload
	payload := packet.ApplicationLayer()
	var payloadBytes []byte
	if payload != nil {
		payloadBytes = payload.Payload()
	}

	fmt.Println("src: ip: " + ip.SrcIP.String() + " port: " + fmt.Sprint(tcp.SrcPort) + " mac: " + eth.SrcMAC.String())
	fmt.Println("dst: ip: " + ip.DstIP.String() + " port: " + fmt.Sprint(tcp.DstPort) + " mac: " + eth.DstMAC.String())

	// modify headers
	eth.DstMAC, err = net.ParseMAC(destAddress.Mac)
	if err != nil {
		log.Println("Error parsing MAC address:", err)
		return
	}
	ip.DstIP = net.ParseIP(destAddress.Ip)
	tcp.DstPort = layers.TCPPort(destAddress.Port)
	eth.SrcMAC, err = net.ParseMAC(proxyAddress.Mac)
	if err != nil {
		log.Println("Error parsing MAC address:", err)
		return
	}
	ip.SrcIP = net.ParseIP(proxyAddress.Ip)
	tcp.SrcPort = layers.TCPPort(proxyAddress.Port)

	// Recalculate checksums
	ip.Checksum = 0
	tcp.Checksum = 0

	err = tcp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Println("Error setting network layer for checksum:", err)
		return
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(
		buffer,
		options,
		eth,
		ip,
		tcp,
		gopacket.Payload(payloadBytes),
	)
	if err != nil {
		log.Println("Error serializing layers:", err)
		return
	}

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Println("Error sending packet:", err)
		return
	}
	fmt.Println("src: ip: " + proxyAddress.Ip + " port: " + fmt.Sprint(proxyAddress.Port) + " mac: " + proxyAddress.Mac)
	fmt.Println("dst: ip: " + destAddress.Ip + " port: " + fmt.Sprint(destAddress.Port) + " mac: " + destAddress.Mac)
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

func main() {
	InitConfig()
	go HandleClientConnection()
	go HandleServerConnection()
	select {}
}
