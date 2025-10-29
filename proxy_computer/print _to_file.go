package main

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var pcapFileName string

func InitPcapFile(filename string, snaplen uint32, linktype layers.LinkType) (error) {
	pcapFileName = filename
	pcapFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer pcapFile.Close()

	pcapWriter := pcapgo.NewWriter(pcapFile)
	err = pcapWriter.WriteFileHeader(snaplen, linktype)
	if err != nil {
		pcapFile.Close()
		return err
	}

	return nil
}

func PrintPacketToPcapFile(captureInfo gopacket.CaptureInfo, data []byte) error {
	pcapFile, err := os.OpenFile(pcapFileName, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer pcapFile.Close()

	pcapWriter := pcapgo.NewWriter(pcapFile)
	err = pcapWriter.WritePacket(captureInfo, data)
	if err != nil {
		return err
	}

	return nil
}
