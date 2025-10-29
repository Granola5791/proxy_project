package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
)

func main() {
	var msg string
	conn, err := net.Dial("tcp", "192.168.1.50:8081")
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()
	msg = "Hello from desktop computer"
	_, _ = conn.Write([]byte(msg + "\n"))
	fmt.Println("Message sent to server.")

	resp, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Printf("Server response: %s", resp)
}
