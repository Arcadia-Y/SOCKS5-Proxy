package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"proxy/base"
	"proxy/reverse"
	"strconv"
)

func ClientListen(port net.Listener, proxyAddress []string, rule *Rules, res *reverse.ReverseServer) {
	for {
		receiver, err := port.Accept()
		if err != nil {
			fmt.Println("Failed to accept user request:", err)
			continue
		}
		go handleRequest(receiver, proxyAddress, rule, res)
	}
}

func handleRequest(receiver net.Conn, proxyAddr []string, rule *Rules, res *reverse.ReverseServer) {
	err := base.Auth(receiver)
	if err != nil {
		fmt.Println("Authentication failed:", err)
		receiver.Close()
		return
	}
	atyp, addr, port, err := base.GetDest(receiver)
	if err != nil {
		fmt.Println("Connection failed:", err)
		receiver.Close()
		return
	}
	// check programRule
	info := ""
	isMatch, name, err := rule.MatchCmd(receiver)
	info = "match ProgramKeyword: " + name
	if err != nil {
		fmt.Println("Failed to get program info:", err)
		receiver.Close()
		return
	}
	if isMatch {
		directConnect(receiver, atyp, addr, port, []byte{}, info, true, res)
		return
	}
	// check addressRule
	if atyp == 3 {
		isMatch, name = rule.MatchKeyword(addr)
		if isMatch {
			info = "match HostnameKeyword: " + name
		}
	} else {
		isMatch, name = rule.MatchCIDR(net.ParseIP(addr))
		if isMatch {
			info = "match CIDR: " + name
		}
	}
	if isMatch {
		directConnect(receiver, atyp, addr, port, []byte{}, info, true, res)
		return
	}
	// check httpRule
	base.WriteResponse(receiver, net.ParseIP("1.2.3.4"), 8080)
	isMatch, name, tosend := rule.MatchHttp(receiver)
	info = "match HttpKeyword: " + name
	if isMatch {
		directConnect(receiver, atyp, addr, port, tosend, info, false, res)
		return
	}
	// proxy
	proxyConnect(receiver, proxyAddr, atyp, addr, port, tosend, res)
}

func directConnect(receiver net.Conn, atyp int, addr string, port uint16, tosend []byte, info string, needRe bool, res *reverse.ReverseServer) {
	res.Redirect(&atyp, &addr, &port)
	if atyp == 4 {
		addr = "[" + addr + "]"
	}
	destAddr := fmt.Sprintf("%s:%d", addr, port)
	dest, err := base.TryDial(receiver, destAddr)
	if err != nil {
		fmt.Println("Connection failed:", err)
		receiver.Close()
		return
	}

	if needRe {
		localAddr := dest.LocalAddr()
		ip := localAddr.(*net.TCPAddr).IP
		port = uint16(localAddr.(*net.TCPAddr).Port)
		err = base.WriteResponse(receiver, ip, port)
		if err != nil {
			receiver.Close()
			dest.Close()
			fmt.Println("Error:", err)
			return
		}
	}

	fmt.Println("[DIRECT]:", destAddr, "   ", info)
	dest.Write(tosend)
	base.Forward(receiver, dest)
}

func proxyConnect(receiver net.Conn, proxyAddr []string, atyp int, addr string, port uint16, tosend []byte, res *reverse.ReverseServer) {
	res.Redirect(&atyp, &addr, &port)
	sender, err := base.TryDial(receiver, proxyAddr[0])
	if err != nil {
		fmt.Println("Connection failed:", err)
		receiver.Write([]byte{5, 1})
		receiver.Close()
		return
	}

	for i := 1; i < len(proxyAddr); i++ {
		err = clientAuth(sender)
		if err != nil {
			fmt.Println("Authentication failed:", err)
			receiver.Write([]byte{5, 1})
			receiver.Close()
			sender.Close()
			return
		}
		pAddr, pPortStr, _ := net.SplitHostPort(proxyAddr[i])
		pPort, _ := strconv.Atoi(pPortStr)
		_, _, err = clientConnect(sender, atyp, pAddr, uint16(pPort))
		if err != nil {
			fmt.Println("Connection failed:", err)
			receiver.Write([]byte{5, 1})
			receiver.Close()
			sender.Close()
			return
		}
	}

	err = clientAuth(sender)
	if err != nil {
		fmt.Println("Authentication failed:", err)
		receiver.Write([]byte{5, 1})
		receiver.Close()
		sender.Close()
		return
	}
	_, _, err = clientConnect(sender, atyp, addr, port)
	if err != nil {
		fmt.Println("Connection failed:", err)
		receiver.Write([]byte{5, 1})
		receiver.Close()
		sender.Close()
		return
	}

	if atyp == 4 {
		addr = "[" + addr + "]"
	}
	destAddr := fmt.Sprintf("%s:%d", addr, port)
	fmt.Println("[PROXY]:", destAddr)
	sender.Write(tosend)
	base.Forward(receiver, sender)
}

func clientAuth(conn net.Conn) error {
	var buf [2]byte
	conn.Write([]byte{5, 1, 0})
	_, err := io.ReadFull(conn, buf[:2])
	if err != nil {
		return err
	}
	if buf[0] != 5 || buf[1] != 0 {
		return err
	}
	return nil
}

func clientConnect(sender net.Conn, atyp int, addr string, port uint16) (bnd_addr string, bnd_port uint16, e error) {
	sender.Write([]byte{5, 1, 0, byte(atyp)})
	// hostname
	if atyp == 3 {
		sender.Write([]byte{uint8(len(addr))})
		sender.Write([]byte(addr))
	} else if atyp == 1 { // ipv4
		ip := net.ParseIP(addr)
		sender.Write([]byte(ip.To4()))
	} else {
		ip := net.ParseIP(addr)
		sender.Write([]byte(ip.To16()))
	}
	var buf [256]byte
	binary.BigEndian.PutUint16(buf[:2], port)
	sender.Write(buf[:2])

	io.ReadFull(sender, buf[:2])
	if buf[0] != 5 || buf[1] != 0 {
		e = fmt.Errorf("reply code: %d", buf[1])
		return
	}
	io.ReadFull(sender, buf[:2])
	switch buf[1] {
	// ipv4
	case 1:
		io.ReadFull(sender, buf[:4])
		ip := net.IPv4(buf[0], buf[1], buf[2], buf[3])
		bnd_addr = ip.String()
	// ipv6
	case 4:
		io.ReadFull(sender, buf[:16])
		ip := net.IP{buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]}
		bnd_addr = ip.String()
	// hostname
	case 3:
		io.ReadFull(sender, buf[:1])
		le := uint8(buf[0])
		io.ReadFull(sender, buf[:le])
		bnd_addr = string(buf[:le])
	default:
		e = errors.New("invalid aytp")
		return
	}

	io.ReadFull(sender, buf[:2])
	bnd_port = binary.BigEndian.Uint16(buf[:2])
	return
}
