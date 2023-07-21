// source code for serverListen
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"proxy/base"
	"syscall"
)

func main() {
	addr := os.Args[1]
	socks5Server, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("Listen failed:", err)
		return
	}
	defer socks5Server.Close()
	fmt.Printf("SOCKS5 Proxy Server is running on %s\n", addr)
	go base.ServerListen(socks5Server)
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	<-signalChannel
}
