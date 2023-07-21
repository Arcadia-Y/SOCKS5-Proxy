package reverse

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"proxy/base"
	"strconv"
	"strings"
)

type ReverseServer struct {
	on       bool
	listener net.Listener
	host     string
	port     uint16
	list     map[string]string
}

func (r *ReverseServer) ParseList(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	r.list = make(map[string]string)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)

	scanner.Scan()
	state := scanner.Text()
	if state == "ON" {
		r.on = true
	} else if state == "OFF" {
		r.on = false
	} else {
		return errors.New("first word should be \"ON\" or \"OFF\"")
	}

	for scanner.Scan() {
		word := scanner.Text()
		scanner.Scan()
		next := scanner.Text()
		r.list[word] = next
	}

	return nil
}

func (r *ReverseServer) Listen(addr string) {
	if !r.on {
		return
	}
	var err error
	r.listener, err = net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("Reverse server failed to listen:", err)
		r.on = false
		r.listener.Close()
		return
	}
	defer r.listener.Close()
	portStr := ""
	r.host, portStr, _ = net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	r.port = uint16(port)
	fmt.Println("Reverse server is listening on", addr)
	r.reserveListen()
}

func (r *ReverseServer) Redirect(atyp *int, addr *string, port *uint16) {
	if !r.on || *atyp != 3 {
		return
	}
	for k := range r.list {
		if k == *addr {
			*atyp = 1
			*addr = r.host
			*port = r.port
			return
		}
	}
}

func (r *ReverseServer) reserveListen() {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept request:", err)
		}
		go r.handleRequest(conn)
	}
}

func (r *ReverseServer) handleRequest(conn net.Conn) {
	var buf [1024]byte
	n, _ := conn.Read(buf[:1024])
	if !strings.Contains(string(buf[:n]), "HTTP") {
		conn.Close()
		fmt.Println("Reverse server only supports HTTP")
		return
	}

	goal := ""
	var tosend []byte
	line := ""
	for i := 0; i < n; i++ {
		if buf[i] != '\r' && buf[i] != '\n' {
			line = line + string(buf[i])
			continue
		}
		if strings.Contains(line, "Host: ") {
			for key, v := range r.list {
				if line[6:] == key {
					line = "Host: " + v
					goal = v + ":80"
				}
			}
		}
		line = line + string(buf[i])
		tosend = append(tosend, line...)
		line = ""
	}
	tosend = append(tosend, line...)

	dest, err := net.Dial("tcp", goal)
	if err != nil {
		conn.Close()
		dest.Close()
		fmt.Println("Reverse server:", err)
		return
	}
	dest.Write(tosend)
	base.Forward(conn, dest)
}
