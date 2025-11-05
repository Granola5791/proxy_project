package main

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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
	var transportTypePrefix string
	portPrefix := GetStringFromConfig("redis.port_key_prefix")
	if isUDP {
		portTTL = time.Duration(GetIntFromConfig("redis.udp_port_ttl")) * time.Second
		ipTTL = time.Duration(GetIntFromConfig("redis.udp_ip_ttl")) * time.Second
		transportTypePrefix = GetStringFromConfig("redis.udp_key_prefix")
	} else {
		portTTL = time.Duration(GetIntFromConfig("redis.tcp_port_ttl")) * time.Second
		ipTTL = time.Duration(GetIntFromConfig("redis.tcp_ip_ttl")) * time.Second
		transportTypePrefix = GetStringFromConfig("redis.tcp_key_prefix")
	}
	exists, err := RedisSetTTL(transportTypePrefix+addr.Ip+":"+addr.Port, ipTTL)
	if err != nil {
		return err
	} else if exists {
		port, err := GetPortByClientAddr(addr, isUDP)
		if err != nil {
			return err
		}
		exists, err := RedisSetTTL(portPrefix+port, portTTL)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New(GetStringFromConfig("error.port_conflict"))
		}
		serverIndex, err := GetServerIndxByClientAddr(addr, isUDP)
		if err != nil {
			return err
		}
		if !GetServerAvailability(serverIndex) {
			return SetNewServer(addr, isUDP)
		}
	} else {
		port, err := GetAvailablePort()
		if err != nil {
			return err
		}
		serverIndex, err := GetNextAvailavleServer()
		if err != nil {
			return err
		}
		err = SetServerIndxAndPortByClientAddr(addr, serverIndex, port, isUDP, ipTTL)
		if err != nil {
			return err
		}
		err = SetClientAddrByPort(addr, port, portTTL)
		if err != nil {
			return err
		}
	}
	return nil
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
			srcPort, err := GetPortByClientAddr(clientAddress, false)
			if err != nil {
				panic(err)
			}
			serverIndex, err := GetServerIndxByClientAddr(clientAddress, false)
			if err != nil {
				panic(err)
			}
			go ForwardTCPPacket(
				packet,
				handle,
				servers[serverIndex],
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
			srcPort, err := GetPortByClientAddr(clientAddress, true)
			if err != nil {
				panic(err)
			}
			serverIndex, err := GetServerIndxByClientAddr(clientAddress, true)
			if err != nil {
				panic(err)
			}
			go ForwardUDPPacket(
				packet,
				handle,
				servers[serverIndex],
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

	err = handle.SetBPFFilter(fmt.Sprintf("dst portrange %d-%d", GetIntFromConfig("redis.first_available_port"), GetIntFromConfig("redis.last_available_port")))
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
			err := HandlePortIn(port)
			if err != nil {
				panic(err)
			}
			clientAddress, err := GetClientAddrByPort(port)
			if err != nil {
				fmt.Println("err: " + err.Error())
				continue
			}
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
			clientAddress, err := GetClientAddrByPort(port)
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
