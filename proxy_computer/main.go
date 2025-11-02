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

	InitRedisClient()

	err = RedisSet("test", "test")
	if err != nil {
		panic(err)
	}
	var val string
	val, err = RedisGet("test")
	if err != nil {
		panic(err)
	}
	fmt.Println(val)

	err = RedisDel("test")
	if err != nil {
		panic(err)
	}
	
	go HandleClientConnection()
	go HandleServerConnection()
	select {}
}
