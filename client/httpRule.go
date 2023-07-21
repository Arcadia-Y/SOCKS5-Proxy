package client

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"
)

func (r *Rules) ParseHttpRules(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	r.http = make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)

	scanner.Scan()
	state := scanner.Text()
	if state == "ON" {
		r.httpON = true
	} else if state == "OFF" {
		r.httpON = false
	} else {
		return errors.New("first word should be \"ON\" or \"OFF\"")
	}

	for scanner.Scan() {
		word := scanner.Text()
		r.http[word] = true
	}
	return nil
}

func (r *Rules) MatchHttp(conn net.Conn) (res bool, key string, tosend []byte) {
	res = false
	if !r.httpON || len(r.http) == 0 {
		return
	}
	var buf [256]byte
	n, _ := conn.Read(buf[:256])
	tosend = append(tosend, buf[:n]...)
	if !strings.Contains(string(buf[:n]), "HTTP") {
		return
	}
	line := ""
	for i := 0; i < n; i++ {
		if buf[i] != '\r' && buf[i] != '\n' {
			line = line + string(buf[i])
			continue
		}
		if strings.Contains(line, "Host: ") {
			for keyword := range r.http {
				if strings.Contains(line[5:], keyword) {
					res = true
					key = keyword
					return
				}
			}
			return
		}
		line = ""
	}
	return
}
