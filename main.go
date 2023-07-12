package main

import (
	"fmt"
	"net"
	"proxy/base"
)

func main() {
	clientAddress := "0.0.0.0:8080"
	socks5Address := "0.0.0.0:1080"
	client, err := net.Listen("tcp", clientAddress)
	if err != nil {
		fmt.Println("Listen failed:", err)
		return
	}
	defer client.Close()
	fmt.Printf("Proxy Client is running on %s\n", clientAddress)

	socks5Server, err := net.Listen("tcp", socks5Address)
	if err != nil {
		fmt.Println("Listen failed:", err)
		return
	}
	defer socks5Server.Close()
	fmt.Printf("SOCKS5 Proxy Server is running on %s\n", socks5Address)

	go serverListen(socks5Server)
	for {
		conn1, err := client.Accept()
		if err != nil {
			fmt.Println("Failed to accept user request:", err)
			continue
		}
		conn2, err := net.Dial("tcp", socks5Address)
		if err != nil {
			fmt.Println("Failed to dial proxy server:", err)
			continue
		}
		go base.Forward(conn1, conn2)
	}
}

func serverListen(port net.Listener) {
	for {
		conn, err := port.Accept()
		if err != nil {
			fmt.Println("Failed to accept client request:", err)
		}
		go base.HandleRequest(conn)
	}
}
