package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ForwardPacket(packet gopacket.Packet, handle *pcap.Handle, destAddress Address, proxyAddress Address) {

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