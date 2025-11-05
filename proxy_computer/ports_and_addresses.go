package main

import (
	"fmt"
	"log"
	"strings"
	"time"
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

func GetClientAddrByPort(port string) (Address, error) {
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

func SetClientAddrByPort(addr Address, port string, ttl time.Duration) error {
	return RedisSet(
		GetStringFromConfig("redis.port_key_prefix")+port,
		fmt.Sprintf("%s,%s,%s", addr.Mac, addr.Ip, addr.Port),
		ttl,
	)
}

func SetServerAddrAndPortByClientAddr(clientAddr Address, serverAddr Address, port string, isUDP bool, ttl time.Duration) error {
	var transportTypePrefix string
	if isUDP {
		transportTypePrefix = GetStringFromConfig("redis.udp_key_prefix")
	} else {
		transportTypePrefix = GetStringFromConfig("redis.tcp_key_prefix")
	}
	err := RedisHSetWithTTL(
		transportTypePrefix+clientAddr.Ip+":"+clientAddr.Port,
		GetStringFromConfig("redis.server_addr_field"),
		fmt.Sprintf("%s,%s,%s", serverAddr.Mac, serverAddr.Ip, serverAddr.Port),
		ttl,
	)
	if err != nil {
		return err
	}
	return RedisHSet(
		transportTypePrefix+clientAddr.Ip+":"+clientAddr.Port,
		GetStringFromConfig("redis.port_field"),
		port,
	)
}
