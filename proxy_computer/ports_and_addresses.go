package main

import (
	"log"
	"strings"
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

func GetServerAddrByClientAddr(addr Address, isUDP bool) (server Address, err error) {
	var transportTypePrefix string
	serverAddrField := GetStringFromConfig("redis.server_addr_field")
	if isUDP {
		transportTypePrefix = GetStringFromConfig("redis.udp_key_prefix")
	} else {
		transportTypePrefix = GetStringFromConfig("redis.tcp_key_prefix")
	}
	res, err := RedisHGet(transportTypePrefix+addr.Ip+":"+addr.Port, serverAddrField)
	if err != nil {
		return Address{}, err
	}
	return ParseAddr(res), nil
}

func GetPortByClientAddr(addr Address, isUDP bool) (port string, err error) {
	var transportTypePrefix string
	portField := GetStringFromConfig("redis.port_field")
	if isUDP {
		transportTypePrefix = GetStringFromConfig("redis.udp_key_prefix")
	} else {
		transportTypePrefix = GetStringFromConfig("redis.tcp_key_prefix")
	}
	res, err := RedisHGet(transportTypePrefix+addr.Ip+":"+addr.Port, portField)
	if err != nil {
		return "", err
	}
	return res, nil
}