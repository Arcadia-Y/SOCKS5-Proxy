package base

import (
	"net"
	"fmt"
	"errors"
	"io"
	"encoding/binary"
	"strings"
)

func HandleRequest(conn net.Conn) {
	err := auth(conn)
	if err != nil {
		fmt.Println("Authentication failed:", err)
		conn.Close();
		return;
	}
	target, err := connect(conn)
	if err != nil {
		fmt.Println("Connection failed:", err)
		conn.Close();
		return;
	}
	Forward(conn, target)
}

func auth(conn net.Conn) error {
	var buf [256]byte
	n, err := io.ReadFull(conn, buf[:2])
	if n != 2 || err != nil {
		return errors.New("failed to read header")
	}
	ver, nmethods := buf[0], int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}
	n, err = io.ReadFull(conn, buf[:nmethods])
	if n != nmethods || err != nil {
		return errors.New("failed to read methods")
	}
	// no auth for now
	flag := false
	for i := 0; i < nmethods; i++ {
		if (buf[i] == 0) {
			flag = true
			break
		}
	}
	method := byte(0x00)
	if (!flag) {
		method = 0xff
	}

	n, err = conn.Write([]byte{0x05, method})
	if n != 2 || err != nil {
		return errors.New("failed to write response")
	}
	if (!flag) {
		return errors.New("method not supported")
	}
	return nil
}

func connect(client net.Conn) (net.Conn, error) {
	var buf [256] byte
	n, err := io.ReadFull(client, buf[:4])
	if n != 4 || err != nil {
		return nil, errors.New("failed to read header")
	}
	ver, cmd, _, atyp := int(buf[0]), int(buf[1]), buf[2], int(buf[3])
	if ver != 5 {
		return nil, errors.New("invalid version")
	}
	// only support CMD CONNECT
	if cmd != 1 {
		client.Write([]byte{5, 7})
		return nil, errors.New("invalid cmd")
	}
	
	addr := ""
	switch atyp {
	// IPv4
	case 1:
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 || err != nil {
			return nil, errors.New("failed to read IPv4 address")
		}
		ip := net.IP(buf[:4])
		addr = ip.String()
	// hostname
	case 3:
		n, err = io.ReadFull(client, buf[:1])
		if n != 1 || err != nil {
			return nil, errors.New("failed to read hostname")
		}
		addrLen := int(buf[0])
		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen || err != nil {
			return nil, errors.New("failed to read hostname")
		}
		addr = string(buf[:addrLen])
	// IPv6
	case 4:
		n, err = io.ReadFull(client, buf[:16])
		if n != 16 || err != nil {
			return nil, errors.New("failed to read IPv6 address")
		}
		ip := net.IP(buf[:16])
		addr = "[" + ip.String() + "]"
	default:
		client.Write([]byte{5, 8})
		return nil, errors.New("invalid atyp")
	}

	n, err = io.ReadFull(client, buf[:2])
	if n != 2 || err != nil {
		return nil, errors.New("failed to read port")
	}
	port := binary.BigEndian.Uint16(buf[:2])

	destAddr := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddr)
	if err != nil {
		if (strings.Contains(err.Error(), "connection refused")) {
			client.Write([]byte{5, 5})
		} else if (strings.Contains(err.Error(), "lookup invalid")) {
			client.Write([]byte{5, 4})
		} else if (strings.Contains(err.Error(), "network is unreachable")) {
			client.Write([]byte{5, 3})
		}
		return nil, errors.New(err.Error())
	}
	
	localAddr := dest.LocalAddr()
	ip := localAddr.(*net.TCPAddr).IP
	port = uint16(localAddr.(*net.TCPAddr).Port)
	isIPv4 := true
	if ip.To4() == nil {
		isIPv4 = false
	}

	buf[0], buf[1], buf[2] = 5, 0, 0
	if isIPv4 {
		buf[3] = 1
		copy(buf[4:8], ip.To4())
		binary.BigEndian.PutUint16(buf[8:10], port)
		_, err = client.Write(buf[:10])
	} else {
		buf[3] = 4
		copy(buf[4:20], ip.To16())
		binary.BigEndian.PutUint16(buf[20:22], port)
		_, err = client.Write(buf[:22])
	}
	if err != nil {
		dest.Close()
		return nil, errors.New("failed to write response")
	}
	fmt.Println("Connection established:", destAddr)
	//fmt.Println(client.RemoteAddr().String(), "->", client.LocalAddr().String())
	//fmt.Println(dest.LocalAddr().String(), "->", dest.RemoteAddr().String())
	return dest, nil
}

func Forward(client, target net.Conn) {
	forwarding := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
	}
	go forwarding(client, target)
	go forwarding(target, client)
}
