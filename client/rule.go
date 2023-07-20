package client

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
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

func (r *Rules) ParseProgramRules(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	r.program = make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		word := scanner.Text()
		r.program[word] = true
	}
	return nil
}

func (r *Rules) MatchCmd(conn net.Conn) (bool, string, error) {
	cmd, err := GetCmd(conn)
	if err != nil {
		return false, "", err
	}
	for key := range r.program {
		if strings.Contains(cmd, key) {
			return true, key, nil
		}
	}
	return false, "", nil
}

func ipToHex(ip string) string {
	host, port, _ := net.SplitHostPort(ip)
	var split [4]int
	j := 0
	for i := 0; i < len(host); i++ {
		if host[i] == '.' {
			j++
			continue
		}
		split[j] = split[j]*10 + int(host[i]-'0')
	}
	var splitStr [4]string
	for i := 0; i < 4; i++ {
		splitStr[i] = fill0(fmt.Sprintf("%X", split[3-i]), 2)
	}
	portInt, _ := strconv.Atoi(port)
	port = fill0(fmt.Sprintf("%X", portInt), 4)
	return fmt.Sprintf("%s%s%s%s:%s", splitStr[0], splitStr[1], splitStr[2], splitStr[3], port)
}

func fill0(s string, digit int) string {
	for len(s) < digit {
		s = "0" + s
	}
	return s
}

func isNumber(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

func GetCmd(conn net.Conn) (ret string, err error) {
	local := ipToHex(conn.RemoteAddr().String())
	remote := ipToHex(conn.LocalAddr().String())

	tcpFile, err := os.Open("/proc/net/tcp")
	if err != nil {
		return
	}
	defer tcpFile.Close()
	scanner := bufio.NewScanner(tcpFile)
	var inode string
	scanner.Scan() // ignore title
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		localAddr := fields[1]
		remoteAddr := fields[2]
		if localAddr == local && remoteAddr == remote {
			inode = fields[9]
			break
		}
	}
	if inode == "" {
		return
	}
	goal := "socket:[" + inode + "]"

	proc, err := os.Open("/proc")
	if err != nil {
		return
	}
	defer proc.Close()
	fileinfos, err := proc.Readdir(-1)
	if err != nil {
		return
	}

	for _, fileinfo := range fileinfos {
		if !(fileinfo.IsDir() && isNumber(fileinfo.Name())) {
			continue
		}
		pid := fileinfo.Name()
		cmd := exec.Command("ls", "-l", fmt.Sprintf("/proc/%s/fd", pid))
		output, _ := cmd.Output()

		if strings.Contains(string(output), goal) {
			cmd, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid))
			for i, c := range cmd {
				if c == 0 {
					cmd[i] = 32
				}
			}
			ret = string(cmd)
			return
		}
	}
	return
}
