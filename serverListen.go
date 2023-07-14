// source code for serverListen
package main

import (
	"fmt"
	"net"
	"os"
	"proxy/base"
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
	base.ServerListen(socks5Server)
}
