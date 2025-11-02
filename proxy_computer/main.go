package main

import (
	"fmt"

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
	
	fmt.Println("initialized redis")
	go HandleClientConnection()
	go HandleServerConnection()
	select {}
}
