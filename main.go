package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	CheckDomainTimeoutMS = flag.Int("timeout", 1000, "Timeout for every one check in milliseconds")
	Parallel             = flag.Int("parallel", 10, "Parallel check count")
	HTTPSPort            = flag.String("port", "443", "What port check")
	IPNetworksFileName   = flag.String("networks", "", "Path to file with allowable ip/networks for connect to check domain. One network/subnet or ip address per line. Can use #-styled comments. Allow all by default.")
)

var (
	CheckDomainTimeout time.Duration
)

type Task struct {
	Domain        string
	AllowNetworks *[]net.IPNet
	Result        string
}

var AllowedNetworks *[]net.IPNet

func main() {
	flag.Usage = usage
	flag.Parse()

	// Parse allowable ip mask
	if *IPNetworksFileName != "" {
		AllowedNetworks = parseNetworksFile(*IPNetworksFileName)
	}

	CheckDomainTimeout = time.Millisecond * time.Duration(*CheckDomainTimeoutMS)

	var tasks = make(chan Task, *Parallel)
	var results = make(chan Task, *Parallel)

	// Read domains in background
	go func() {
		if flag.NArg() == 0 {
			stdinReader(tasks)
		} else {
			filesReader(tasks, flag.Args()...)
		}
		close(tasks)
	}()

	// Start check domains
	var wg = sync.WaitGroup{}
	for i := 0; i < *Parallel; i++ {
		wg.Add(1) // Out of go func - for sync increment
		go func() {
			for task := range tasks {
				checkDomain(&task)
				results <- task
			}
			wg.Done()
		}()
	}

	// Close out channel when all checkers complere work
	go func() {
		wg.Wait()
		close(results)
	}()

	// Output results
	for res := range results {
		fmt.Printf("%v: %v\n", res.Domain, res.Result)
	}
}

func usage() {
	fmt.Printf(`%v [options] [file1 file2 ...]
file1 file2 ... - files with list of domains to check.
If no files - use stdinput

List of domains: one or several domains per line. In a line domain separated by comma.
Example:
domain.ru
domain2.ru,www.domain2.ru

options:
`, os.Args[0])

	flag.PrintDefaults()
}

func checkDomain(task *Task) {
	var res []string

	defer func() {
		task.Result = strings.Join(res, "; ")
	}()

	ips, err := net.LookupIP(task.Domain)
	if err != nil {
		res = append(res, "Error while domain lookup: "+err.Error())
		return
	}
	if len(ips) == 0 {
		res = append(res, "No ip addresses for the domain")
		return
	}

	for _, ip := range ips {
		if AllowedNetworks != nil {
			ipAllowed := false
			for _, network := range *AllowedNetworks {
				ipString := ip.String()
				ipnetString := network.String()
				if ipString == ipnetString {

				}
				if network.Contains(ip) {
					ipAllowed = true
					break
				}
			}
			if !ipAllowed {
				res = append(res, "IP address denied by network filters: "+ip.String())
				continue
			}
		}

		func() {
			deadLine := time.Now().Add(CheckDomainTimeout)
			conn, err := net.DialTimeout("tcp", ip.String()+":"+*HTTPSPort, CheckDomainTimeout)
			if err != nil {
				res = append(res, fmt.Sprintf("Error while connect to IP: %v (%v)", ip, err))
				return
			}
			defer conn.Close()

			tlsConn := tls.Client(conn, &tls.Config{ServerName: task.Domain})
			tlsConn.SetDeadline(deadLine)
			err = tlsConn.Handshake()
			if err != nil {
				errString := err.Error()
				res = append(res, fmt.Sprintf("Error while handshake to IP '%v': %v", ip, errString))
				return
			}
			res = append(res, "OK: "+ip.String())
		}()
	}
}

func filesReader(tasks chan<- Task, files ...string) {
	for _, fileName := range files {
		func() {
			f, err := os.Open(fileName)
			if err != nil {
				log.Printf("Can't open input file '%v': %v\n", fileName, err)
				return
			}
			defer f.Close()
			log.Printf("Read file '%v'\n", fileName)

			scanner := bufio.NewScanner(f)
			scanner.Split(splitDomains)
			for scanner.Scan() {
				tasks <- Task{Domain: scanner.Text()}
			}
			if scanner.Err() != nil {
				fmt.Printf("Error while read input file '%v': %v\n", fileName, scanner.Err())
			}
		}()
	}
}

func parseNetworksFile(fname string) *[]net.IPNet {
	var res = []net.IPNet{}
	f, err := os.Open(fname)
	if err != nil {
		log.Fatalf("Can't open ip filters file '%v': %v\n", fname, err)
	}
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		// Cut comment
		if strings.Index(line, "#") != -1 {
			line = line[:strings.Index(line, "#")]
		}
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if strings.Index(line, "/") != -1 {
			// CIDR
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				log.Printf("Error while parse filters file '%v' line %v (%v):%v (CIDR)\n", fname, lineNum, line, err)
				continue
			}
			res = append(res, *ipnet)
		} else {
			ip := net.ParseIP(line)
			switch {

			case ip == nil:
				log.Printf("Error while parse filters file '%v' line %v (%v). (IP)\n", fname, lineNum, line)
				continue
			case ip.To4() != nil:
				res = append(res, net.IPNet{IP: ip, Mask: net.CIDRMask(8*net.IPv4len, 8*net.IPv4len)})
			case len(ip) == net.IPv6len:
				res = append(res, net.IPNet{IP: ip, Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len)})
			default:
				log.Printf("Undetected ip address type: %v\n", line)
			}
		}
	}
	if scanner.Err() != nil {
		log.Fatal("Error while read fileter file '%v': %v\n", fname, scanner.Err())
	}
	return &res
}

func stdinReader(tasks chan<- Task) {
	fmt.Println("Read stdin")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Split(splitDomains)
	for scanner.Scan() {
		tasks <- Task{Domain: scanner.Text()}
	}
	if scanner.Err() != nil {
		log.Printf("Error while read domains: %v\n", scanner.Err())
	}
}

func splitDomains(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// copy of bufio.ScanWords, but add comma separator

	// Skip leading spaces and commas
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !(unicode.IsSpace(r) || r == ',') {
			break
		}
	}
	// Scan until space or comma, marking end of word.
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])
		if unicode.IsSpace(r) || r == ',' {
			advance, token, err = i+width, data[start:i], nil
			return
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
	if atEOF && len(data) > start {
		advance, token, err = len(data), data[start:], nil
		return
	}
	// Request more data.
	advance, token, err = start, nil, nil
	return
}
