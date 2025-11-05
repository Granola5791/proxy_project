package main

import (
	"errors"
	"fmt"
	"net"
	"time"
)

var availableServers *BitMap
var servers []Address
var currAvailableServerIndex int

func AssignServerIps() {
	servers = []Address{
		{
			Mac:  GetStringFromConfig("addresses.server1_mac"),
			Ip:   GetStringFromConfig("addresses.server1_ip"),
			Port: GetStringFromConfig("addresses.server1_port"),
		},
		{
			Mac:  GetStringFromConfig("addresses.server2_mac"),
			Ip:   GetStringFromConfig("addresses.server2_ip"),
			Port: GetStringFromConfig("addresses.server2_port"),
		},
		{
			Mac:  GetStringFromConfig("addresses.server3_mac"),
			Ip:   GetStringFromConfig("addresses.server3_ip"),
			Port: GetStringFromConfig("addresses.server3_port"),
		},
	}
}

func InitServersAvailability() {
	for i := range servers {
		UpdateServerAvailability(i)
	}
}

func InitServers() {
	availableServers = NewBitMap()
	AssignServerIps()
	InitServersAvailability()
	go ConstantlyUpdateServersAvailability()
}

func GetServerAvailability(index int) bool {
	return availableServers.GetBit(index)
}

func SetServerAvailability(index int, available bool) {
	if available {
		availableServers.SetBitOn(index)
	} else {
		availableServers.SetBitOff(index)
	}
}

func GetNextAvailavleServer() (int, error) {
	if availableServers.IsEmpty() {
		return 0, errors.New(GetStringFromConfig("error.no_available_servers"))
	}

	temp := currAvailableServerIndex
	currAvailableServerIndex = (currAvailableServerIndex + 1) % len(servers)
	for !GetServerAvailability(currAvailableServerIndex) && currAvailableServerIndex != temp {
		currAvailableServerIndex = (currAvailableServerIndex + 1) % len(servers)
	}
	if !GetServerAvailability(currAvailableServerIndex) {
		return 0, errors.New(GetStringFromConfig("error.no_available_servers"))
	}
	return currAvailableServerIndex, nil

}

func isServerUp(server Address) bool {
	timeout := time.Duration(GetIntFromConfig("servers.availability_check_timeout_sec")) * time.Second
	conn, err := net.DialTimeout("tcp", server.Ip+":"+server.Port, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func UpdateServerAvailability(index int) {
	isUp := isServerUp(servers[index])
	SetServerAvailability(index, isUp)

	if !isUp {
		fmt.Println("Server", servers[index].Ip, "is down")
	} else {
		fmt.Println("Server", servers[index].Ip, "is up")
	}
}

func ConstantlyUpdateServersAvailability() {
	interval := time.Duration(GetIntFromConfig("servers.availability_check_interval_sec")) * time.Second
	for {
		for i := range servers {
			go UpdateServerAvailability(i)
		}
		time.Sleep(interval)
	}
}
