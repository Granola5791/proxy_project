package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
)

func HandleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("Client connected: %s\n", clientAddr)

	reader := bufio.NewReader(conn)

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Printf("Client disconnected: %s\n", clientAddr)
			} else {
				log.Printf("Error reading from client %s: %v", clientAddr, err)
			}
			return
		}
		fmt.Printf("Received from %s: %s", clientAddr, message)

		response := fmt.Sprintf("Server echo: %s\n", message)

		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Printf("Error writing to client %s: %v", clientAddr, err)
			return
		}
		fmt.Printf("-> Sent to %s: %s\n", clientAddr, response)
	}

}

func main() {
	listener, err := net.Listen("tcp", "192.168.1.60:9090")
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer listener.Close()

	fmt.Println("Server is listening on port 9090")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Failed to accept connection: %v", err)
		}
		go HandleConnection(conn)
	}

}
