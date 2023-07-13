package main

import (
	"fmt"
	"net"
	"proxy/base"
	"proxy/client"
)

func main() {
	clientAddress := "0.0.0.0:8080"
	socks5Address := "0.0.0.0:1080"

	var socksRule client.Rules
	err := socksRule.ParseRules("socksRule.db")
	if err != nil {
		fmt.Println("Failed to parse rules:", err)
		return
	}

	proxyClient, err := net.Listen("tcp", clientAddress)
	if err != nil {
		fmt.Println("Listen failed:", err)
		return
	}
	defer proxyClient.Close()
	fmt.Printf("Proxy Client is running on %s\n", clientAddress)

	socks5Server, err := net.Listen("tcp", socks5Address)
	if err != nil {
		fmt.Println("Listen failed:", err)
		return
	}
	defer socks5Server.Close()
	fmt.Printf("SOCKS5 Proxy Server is running on %s\n", socks5Address)

	go base.ServerListen(socks5Server)
	client.ClientListen(proxyClient, socks5Address, &socksRule)
}
