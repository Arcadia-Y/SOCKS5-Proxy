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
	keyword map[string]bool
	cidr    map[*net.IPNet]bool
	program map[string]bool
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
	for key := range r.cidr {
		if key.Contains(x) {
			return true, key.String()
		}
	}
	return false, ""
}

func (r *Rules) MatchKeyword(x string) (bool, string) {
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

func ParseProxyAddr(name string) ([]string, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ret []string
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		word := scanner.Text()
		if !checkAddr(word) {
			return nil, errors.New("invalid proxy address")
		}
		ret = append(ret, word)
	}
	if len(ret) == 0 {
		return nil, errors.New("no proxy address found")
	}
	return ret, nil
}
