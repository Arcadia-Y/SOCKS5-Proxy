// main program
package main

import (
	"fmt"
	"net"
	"os/exec"
	"proxy/client"
)

func main() {
	clientAddress := "0.0.0.0:8080"
	proxyAddr, err := client.ParseProxyAddr("proxyAddr.db")
	if err != nil {
		fmt.Println("Failed to parse proxy address:", err)
		return
	}

	var socksRule client.Rules
	err = socksRule.ParseRules("socksRule.db")
	if err != nil {
		fmt.Println("Failed to parse rules:", err)
		return
	}
	err = socksRule.ParseProgramRules("programRule.db")
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
	fmt.Printf("Proxy Client is listening on %s\n", clientAddress)

	for _, addr := range proxyAddr {
		cmd := exec.Command("./serverListen", addr)
		cmd.Start()
		defer cmd.Process.Kill()
		fmt.Println("SOCKS5 server is listening on", addr)
	}

	proxyAddr = append(proxyAddr, "127.0.0.1:7891")
	client.ClientListen(proxyClient, proxyAddr, &socksRule)
}
