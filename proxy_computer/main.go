package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Open the network device
	handle, err := pcap.OpenLive("eth0", 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create packet source
	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	// Listen for packets
	fmt.Println("Listening for packets...")
	for packet := range packets.Packets() {
		fmt.Println("Received packet:", packet)
	}
}
