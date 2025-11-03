package main

import (
	"github.com/google/gopacket/layers"
)

func main() {
	InitConfig()

	err := InitEnv()
	if err != nil {
		panic(err)
	}

	err = InitPcapFile(
		GetStringFromConfig("pcap_file_name"),
		GetUint32FromConfig("pcap_snaplen"),
		layers.LinkTypeEthernet,
	)
	if err != nil {
		panic(err)
	}

	InitRedis()
	
	go HandleClientConnection()
	go HandleServerConnection()
	select {}
}
