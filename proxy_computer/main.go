package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func HandleClientConnection() {
	handle, err := pcap.OpenLive(
		GetStringFromConfig("network_device"),
		int32(GetIntFromConfig("pcap_snaplen")),
		false,
		pcap.BlockForever,
	)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.SetBPFFilter("port 8080")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create packet source
	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	// Listen for packets
	fmt.Println("Listening for packets...")
	for packet := range packets.Packets() {
		fmt.Println("Received packet:", packet.NetworkLayer())
	}
}

func main() {
	InitConfig()
	go HandleClientConnection()
	select {}
}
