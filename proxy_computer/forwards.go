package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ForwardTCPPacket(packet gopacket.Packet, handle *pcap.Handle, newDstAddr Address, newSrcAddr Address) {

	// Print to pcap file
	captureInfo := packet.Metadata().CaptureInfo
	data := packet.Data()
	err := PrintPacketToPcapFile(captureInfo, data)
	if err != nil {
		log.Println("Error writing packet to pcap file:", err)
		return
	}

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
	eth.DstMAC, err = net.ParseMAC(newDstAddr.Mac)
	if err != nil {
		log.Println("Error parsing MAC address:", err)
		return
	}
	ip.DstIP = net.ParseIP(newDstAddr.Ip)
	tcp.DstPort = layers.TCPPort(newDstAddr.Port)
	eth.SrcMAC, err = net.ParseMAC(newSrcAddr.Mac)
	if err != nil {
		log.Println("Error parsing MAC address:", err)
		return
	}
	ip.SrcIP = net.ParseIP(newSrcAddr.Ip)
	tcp.SrcPort = layers.TCPPort(newSrcAddr.Port)

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
	fmt.Println("src: ip: " + newSrcAddr.Ip + " port: " + fmt.Sprint(newSrcAddr.Port) + " mac: " + newSrcAddr.Mac)
	fmt.Println("dst: ip: " + newDstAddr.Ip + " port: " + fmt.Sprint(newDstAddr.Port) + " mac: " + newDstAddr.Mac)
}

func ForwardUDPPacket(packet gopacket.Packet, handle *pcap.Handle, newDstAddr Address, newSrcAddr Address) {

	// Print to pcap file
	captureInfo := packet.Metadata().CaptureInfo
	data := packet.Data()
	err := PrintPacketToPcapFile(captureInfo, data)
	if err != nil {
		log.Println("Error writing packet to pcap file:", err)
		return
	}

	// Extract layers
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ethLayer == nil || ipLayer == nil || udpLayer == nil {
		fmt.Println("Packet does not contain required layers")
		return
	}

	// Cast layers to their respective types
	eth := ethLayer.(*layers.Ethernet)
	ip := ipLayer.(*layers.IPv4)
	udp := udpLayer.(*layers.UDP)

	// Get the payload
	payload := packet.ApplicationLayer()
	var payloadBytes []byte
	if payload != nil {
		payloadBytes = payload.Payload()
	}

	// modify headers
	eth.DstMAC, err = net.ParseMAC(newDstAddr.Mac)
	if err != nil {
		log.Println("Error parsing MAC address:", err)
		return
	}
	ip.DstIP = net.ParseIP(newDstAddr.Ip)
	udp.DstPort = layers.UDPPort(newDstAddr.Port)
	eth.SrcMAC, err = net.ParseMAC(newSrcAddr.Mac)
	if err != nil {
		log.Println("Error parsing MAC address:", err)
		return
	}
	ip.SrcIP = net.ParseIP(newSrcAddr.Ip)
	udp.SrcPort = layers.UDPPort(newSrcAddr.Port)

	// Recalculate checksums
	ip.Checksum = 0
	udp.Checksum = 0

	err = udp.SetNetworkLayerForChecksum(ip)
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
		udp,
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
}
