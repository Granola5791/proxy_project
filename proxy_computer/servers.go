package main

import (
	"net"
	"time"
)

var availableServers *BitMap
var serverIps []string
var currAvailableServerIndex int

func AssignServerIps() {
	serverIps = []string{
		GetStringFromConfig("addresses.server1_ip"),
		GetStringFromConfig("addresses.server2_ip"),
		GetStringFromConfig("addresses.server3_ip"),
	}
}

func InitServersAvailability() {
	for i := range serverIps {
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

func GetNextAvailavleServer() (string, error) {
	if availableServers.IsEmpty() {
		return "", nil
	}

	temp := currAvailableServerIndex
	currAvailableServerIndex = (currAvailableServerIndex + 1) % len(serverIps)
	for !GetServerAvailability(currAvailableServerIndex) && currAvailableServerIndex != temp {
		currAvailableServerIndex = (currAvailableServerIndex + 1) % len(serverIps)
	}
	if !GetServerAvailability(currAvailableServerIndex) {
		return "", nil
	}
	return serverIps[currAvailableServerIndex], nil

}

func isServerUp(serverIp string) bool {
	timeout := time.Duration(GetIntFromConfig("servers.availability_check_timeout_sec")) * time.Second
	conn, err := net.DialTimeout("tcp", serverIp, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func UpdateServerAvailability(index int) {
	if isServerUp(serverIps[index]) {
		availableServers.SetBitOn(index)
	}
}

func ConstantlyUpdateServersAvailability() {
	interval := time.Duration(GetIntFromConfig("servers.availability_check_interval_sec")) * time.Second
	for {
		for i := range serverIps {
			go UpdateServerAvailability(i)
		}
		time.Sleep(interval)
	}
}
