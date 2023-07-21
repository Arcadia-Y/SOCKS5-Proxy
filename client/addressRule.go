package client

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
)

type Rules struct {
	addrON  bool
	progON  bool
	httpON  bool
	reverseON bool
	keyword map[string]bool
	cidr    map[*net.IPNet]bool
	program map[string]bool
	http    map[string]bool
	reverse map[string]string
}

func (r *Rules) ParseRules(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	r.keyword = make(map[string]bool)
	r.cidr = make(map[*net.IPNet]bool)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)

	scanner.Scan()
	state := scanner.Text()
	if state == "ON" {
		r.addrON = true
	} else if state == "OFF" {
		r.addrON = false
	} else {
		return errors.New("first word should be \"ON\" or \"OFF\"")
	}

	for scanner.Scan() {
		word := scanner.Text()
		_, ipNet, err := net.ParseCIDR(word)
		// CIDR
		if err == nil {
			r.cidr[ipNet] = true
			continue
		}
		// KEYWORD
		r.keyword[word] = true
	}

	return nil
}

func (r *Rules) MatchCIDR(x net.IP) (bool, string) {
	if !r.addrON {
		return false, ""
	}
	for key := range r.cidr {
		if key.Contains(x) {
			return true, key.String()
		}
	}
	return false, ""
}

func (r *Rules) MatchKeyword(x string) (bool, string) {
	if !r.addrON {
		return false, ""
	}
	for key := range r.keyword {
		if strings.Contains(x, key) {
			return true, key
		}
	}
	return false, ""
}

func checkAddr(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	num, err := strconv.Atoi(port)
	if err != nil || num < 0 || num > 65535 {
		return false
	}
	return true
}
