package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	// "time"
)

func SendTCPMessage(message string) {
	conn, err := net.Dial("tcp", "192.168.1.50:8081")
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()
	fmt.Println("Connected to server.")
	_, _ = conn.Write([]byte(message + "\n"))
	fmt.Println("Message sent to server.")

	resp, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Printf("Server response: %s", resp)

}

func SendUDPMessage(message string) {
	conn, err := net.Dial("udp", "192.168.1.50:8081")
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, message, "\n")
	fmt.Println("Message sent to server.")

	resp := make([]byte, 2048)
	_, err = bufio.NewReader(conn).Read(resp)
	if err != nil {
		log.Fatalf("Failed to read response from server: %v", err)
	}

	fmt.Printf("Server response: %s", resp)
}

func main() {
	fmt.Println("Client started.")
	// for i := 0; i < 10; i++ {
	// SendUDPMessage("Hello, UDP!" + fmt.Sprint(i))
	SendTCPMessage("Hello, TCP!: ")
	// 	time.Sleep(1 * time.Second)
	// }

	// SendTCPMessage("Hello, TCP!")
}
