package main

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Address struct {
	Mac  string
	Ip   string
	Port string
}

func ParseAddr(addr string) Address {
	parts := strings.Split(addr, ",")
	if len(parts) != 3 {
		log.Fatalf("invalid address format: %v", addr)
	}
	return Address{parts[0], parts[1], parts[2]}
}

func GetAddrByPort(port string) (Address, error) {
	addr, err := RedisGet(GetStringFromConfig("redis.port_key_prefix") + port)
	if err != nil {
		return Address{}, err
	}
	return ParseAddr(addr), nil
}

func GetSrcAddressTCP(packet gopacket.Packet) Address {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ethLayer != nil && ipLayer != nil && tcpLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		ip := ipLayer.(*layers.IPv4)
		tcp := tcpLayer.(*layers.TCP)
		return Address{eth.SrcMAC.String(), ip.SrcIP.String(), strconv.Itoa(int(tcp.SrcPort))}
	}
	fmt.Println("cant get address")
	return Address{"", "", ""}
}

func GetSrcAddressUDP(packet gopacket.Packet) Address {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ethLayer != nil && ipLayer != nil && udpLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		ip := ipLayer.(*layers.IPv4)
		udp := udpLayer.(*layers.UDP)
		return Address{eth.SrcMAC.String(), ip.SrcIP.String(), strconv.Itoa(int(udp.SrcPort))}
	}
	return Address{"", "", ""}
}

func GetDstPortTCP(packet gopacket.Packet) string {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return strconv.Itoa(int(tcp.DstPort))
	}
	return ""
}

func GetDstPortUDP(packet gopacket.Packet) string {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return strconv.Itoa(int(udp.DstPort))
	}
	return ""
}

func IsUDP(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeUDP) != nil
}

func IsTCP(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeTCP) != nil
}

func HandlePortOut(addr Address, isUDP bool) error {
	var portTTL time.Duration
	var ipTTL time.Duration
	if isUDP {
		portTTL = time.Duration(GetIntFromConfig("redis.udp_port_ttl")) * time.Second
		ipTTL = time.Duration(GetIntFromConfig("redis.udp_ip_ttl")) * time.Second
	} else {
		portTTL = time.Duration(GetIntFromConfig("redis.tcp_port_ttl")) * time.Second
		ipTTL = time.Duration(GetIntFromConfig("redis.tcp_ip_ttl")) * time.Second
	}
	exists, err := RedisSetTTL(GetStringFromConfig("redis.ip_key_prefix")+addr.Ip, ipTTL)
	if err != nil {
		return err
	} else if exists {
		port, err := RedisGet(GetStringFromConfig("redis.ip_key_prefix") + addr.Ip)
		if err != nil {
			return err
		}
		exists, err := RedisSetTTL(GetStringFromConfig("redis.port_key_prefix")+port, portTTL)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New(GetStringFromConfig("error.port_conflict"))
		}
		return nil
	} else {
		fmt.Println("creating new")
		port, err := GetAvailablePort()
		if err != nil {
			return err
		}
		err = RedisSet(GetStringFromConfig("redis.ip_key_prefix")+addr.Ip, port, ipTTL)
		if err != nil {
			return err
		}
		err = RedisSet(GetStringFromConfig("redis.port_key_prefix")+port, fmt.Sprintf("%s,%s,%s", addr.Mac, addr.Ip, addr.Port), portTTL)
		if err != nil {
			return err
		}
		return nil
	}
}

func HandlePortIn(port string) error {
	exists, err := RedisSetTTL(GetStringFromConfig("redis.port_key_prefix")+port, time.Duration(GetIntFromConfig("redis.tcp_port_ttl"))*time.Second)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New(GetStringFromConfig("error.port_does_not_exist"))
	}
	return nil
}

func HandleClientConnection() {
	var clientAddress Address
	handle, err := pcap.OpenLive(
		GetStringFromConfig("network_device"),
		int32(GetIntFromConfig("pcap_snaplen")),
		GetBoolFromConfig("pcap_promiscuous"),
		pcap.BlockForever,
	)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.SetBPFFilter("dst port " + GetStringFromConfig("addresses.proxy_client_port"))
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create packet source
	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	// Listen for packets
	fmt.Println("Listening for packets...")
	for packet := range packets.Packets() {
		// Print to pcap file
		captureInfo := packet.Metadata().CaptureInfo
		data := packet.Data()
		err := PrintPacketToPcapFile(captureInfo, data)
		if err != nil {
			log.Println("Error writing packet to pcap file:", err)
			return
		}
		if IsTCP(packet) {
			clientAddress = GetSrcAddressTCP(packet)
			err := HandlePortOut(clientAddress, false)
			if err != nil {
				panic(err)
			}
			fmt.Println("client ip: " + clientAddress.Ip)
			srcPort, err := RedisGet(GetStringFromConfig("redis.ip_key_prefix") + clientAddress.Ip)
			if err != nil {
				panic(err)
			}
			go ForwardTCPPacket(
				packet,
				handle,
				Address{
					Mac:  GetStringFromConfig("addresses.server_mac"),
					Ip:   GetStringFromConfig("addresses.server_ip"),
					Port: GetStringFromConfig("addresses.server_port"),
				},
				Address{
					Mac:  GetStringFromConfig("addresses.proxy_mac"),
					Ip:   GetStringFromConfig("addresses.proxy_ip"),
					Port: srcPort,
				},
			)
		} else if IsUDP(packet) {
			clientAddress = GetSrcAddressUDP(packet)
			err := HandlePortOut(clientAddress, true)
			if err != nil {
				panic(err)
			}
			srcPort, err := RedisGet(GetStringFromConfig("redis.ip_key_prefix") + clientAddress.Ip)
			if err != nil {
				panic(err)
			}
			go ForwardUDPPacket(
				packet,
				handle,
				Address{
					Mac:  GetStringFromConfig("addresses.server_mac"),
					Ip:   GetStringFromConfig("addresses.server_ip"),
					Port: GetStringFromConfig("addresses.server_port"),
				},
				Address{
					Mac:  GetStringFromConfig("addresses.proxy_mac"),
					Ip:   GetStringFromConfig("addresses.proxy_ip"),
					Port: srcPort,
				},
			)
		} else {
			fmt.Println("Packet does not contain required layers")
		}
	}
}

func HandleServerConnection() {
	handle, err := pcap.OpenLive(
		GetStringFromConfig("network_device"),
		int32(GetIntFromConfig("pcap_snaplen")),
		GetBoolFromConfig("pcap_promiscuous"),
		pcap.BlockForever,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("src host " + GetStringFromConfig("addresses.server_ip"))
	err = handle.SetBPFFilter("src host " + GetStringFromConfig("addresses.server_ip"))
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create packet source
	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	// Listen for packets
	fmt.Println("Listening for server packets...")
	for packet := range packets.Packets() {
		// Print to pcap file
		captureInfo := packet.Metadata().CaptureInfo
		data := packet.Data()
		err := PrintPacketToPcapFile(captureInfo, data)
		if err != nil {
			log.Println("Error writing packet to pcap file:", err)
			return
		}
		
		fmt.Println("got server packet")
		if IsTCP(packet) {
			port := GetDstPortTCP(packet)
			fmt.Println("port: " + port)
			err := HandlePortIn(port)
			if err != nil {
				panic(err)
			}
			clientAddress, err := GetAddrByPort(port)
			if err != nil {
				fmt.Println("err: " + err.Error())
				continue
			}
			fmt.Println("client ip: " + clientAddress.Ip)
			fmt.Println("client mac: " + clientAddress.Mac)
			fmt.Println("client port: " + clientAddress.Port)
			go ForwardTCPPacket(
				packet,
				handle,
				clientAddress,
				Address{
					Mac:  GetStringFromConfig("addresses.proxy_mac"),
					Ip:   GetStringFromConfig("addresses.proxy_ip"),
					Port: GetStringFromConfig("addresses.proxy_client_port"),
				},
			)
		} else if IsUDP(packet) {
			port := GetDstPortUDP(packet)
			err := HandlePortIn(port)
			if err != nil {
				panic(err)
			}
			clientAddress, err := GetAddrByPort(port)
			if err != nil {
				fmt.Println("err: " + err.Error())
				continue
			}
			go ForwardUDPPacket(
				packet,
				handle,
				clientAddress,
				Address{
					Mac:  GetStringFromConfig("addresses.proxy_mac"),
					Ip:   GetStringFromConfig("addresses.proxy_ip"),
					Port: GetStringFromConfig("addresses.proxy_client_port"),
				},
			)
		} else {
			fmt.Println("Packet does not contain required layers")
		}
	}
}
