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
)

var (
	CheckDomainTimeout time.Duration
)

type Task struct {
	Domain string
	Result string
}

func main() {
	flag.Usage = usage
	flag.Parse()

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
		task.Result = strings.Join(res, "\n")
	}()

	deadLine := time.Now().Add(CheckDomainTimeout)
	ips, err := net.LookupIP(task.Domain)
	if err != nil {
		task.Result = "Error while domain lookup: " + err.Error()
		return
	}
	for _, ip := range ips {
		func() {
			conn, err := net.DialTimeout("tcp", ip.String()+":"+*HTTPSPort, deadLine.Sub(time.Now()))
			if err != nil {
				res = append(res, fmt.Sprintf("Error while connect to IP: %v (%v)", ip, err))
				return
			}
			defer conn.Close()

			tlsConn := tls.Client(conn, &tls.Config{ServerName: task.Domain})
			err = tlsConn.Handshake()
			if err != nil {
				res = append(res, fmt.Sprintf("Error while handshake to IP '%v': %v", ip, err))
				return
			}
		}()
	}
	res = append(res, "OK")
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
