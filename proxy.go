// main program
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"proxy/client"
	"syscall"
)

func main() {
	clientAddress := "0.0.0.0:8080"
	reverseAddr := "127.0.0.1:80"
	var cl client.Client

	err := cl.ParseProxyAddr("proxyAddr.db")
	if err != nil {
		fmt.Println("Failed to parse proxy address:", err)
		return
	}

	err = cl.ParseRules()
	if err != nil {
		fmt.Println("Failed to parse rules:", err)
		return
	}

	err = cl.Res.ParseList("reverseList.db")
	if err != nil {
		fmt.Println("Failed to parse reverseList:", err)
		return
	}
	err = cl.Res.ModifyHost()
	if err != nil {
		fmt.Println("Failed to modify hosts:", err)
		return
	}
	defer cl.Res.RestoreHost()
	go cl.Res.Listen(reverseAddr)

	clientListener, err := net.Listen("tcp", clientAddress)
	if err != nil {
		fmt.Println("Listen failed:", err)
		return
	}
	defer clientListener.Close()
	fmt.Printf("Proxy Client is listening on %s\n", clientAddress)

	for _, addr := range cl.ProxyAddr {
		cmd := exec.Command("./serverListen", addr)
		cmd.Start()
		defer cmd.Process.Kill()
		fmt.Println("SOCKS5 server is listening on", addr)
	}

	cl.ProxyAddr = append(cl.ProxyAddr, "127.0.0.1:7891")
	go cl.Listen(clientListener)
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	<-signalChannel
	cl.End = true
	fmt.Println("\nExit")
}
