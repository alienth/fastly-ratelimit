package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/juju/ratelimit"
)

// getIPs takes in an haproxy log line and returns the client IP and the CDN
// connecting IP which is in the captured request header. For us, the CDN
// connecting IP happens to be the 8th captured request header.
func getIPs(logLine string) (*net.IP, *net.IP) {
	if logLine == "" {
		return nil, nil
	}
	// This string parsing stuff was lifted from TPS
	var a, b int
	if a = strings.Index(logLine, "]:") + 3; a == -1 {
		return nil, nil
	}
	if b = strings.Index(logLine[a:], ":"); b == -1 {
		return nil, nil
	}
	clientIPString := logLine[a : a+b]
	clientIP := net.ParseIP(clientIPString)
	if clientIP == nil {
		return nil, nil
	}

	logLine = logLine[a+b:]
	// The first curly-braced block contains our request headers
	if a = strings.Index(logLine, "{"); a == -1 {
		return &clientIP, nil
	}
	if b = strings.Index(logLine[a:], "}"); b == -1 {
		return &clientIP, nil
	}
	bracketedHeaders := logLine[a : a+b]
	headers := strings.Split(bracketedHeaders, "|")
	if len(headers) < 7 {
		return &clientIP, nil
	}
	ipString := headers[7]
	cdnIP := net.ParseIP(ipString)
	if cdnIP == nil {
		return &clientIP, nil
	}
	return &clientIP, &cdnIP
}

func getLogTimestamp(logLine string) int64 {
	timestampStr := strings.Split(logLine, " ")[6]
	ts, _ := time.Parse("[02/Jan/2006:15:04:05.999]", timestampStr)

	return (ts.Unix())
}

type ipList struct {
	ips  []net.IP
	nets []net.IPNet
}

func readIPList(filename string) *ipList {
	var list ipList
	f, _ := os.Open(filename)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Index(strings.TrimSpace(line), "#") == 0 {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "/") {
			_, n, err := net.ParseCIDR(line)
			if err != nil {
				fmt.Printf("Unable to parse CIDR.\nLine:\n%s\nError:\n%s\n", line, err)
			}
			if n != nil {
				list.nets = append(list.nets, *n)
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				list.ips = append(list.ips, ip)
			} else {
				fmt.Printf("Unable to parse IP address in list: %s\n", line)
			}
		}

	}
	return &list
}

func (l *ipList) contains(checkIP *net.IP) bool {
	for _, ip := range l.ips {
		if ip.Equal(*checkIP) {
			return true
		}
	}
	for _, net := range l.nets {
		if net.Contains(*checkIP) {
			return true
		}
	}

	return false
}

func main() {
	//	t, err := tail.TailFile(os.Args[1], tail.Config{Follow: true})
	//if err != nil {
	//	fmt.Println(err)
	//}
	var hits map[string]*ratelimit.Bucket
	hits = make(map[string]*ratelimit.Bucket)
	//	for line := range t.Lines {
	scanner := bufio.NewScanner(os.Stdin)
	whitelist := readIPList("/etc/haproxy-shared/whitelist-ips")
	for scanner.Scan() {
		line := scanner.Text()
		clientIP, cdnIP := getIPs(line)
		if cdnIP == nil || clientIP == nil {
			continue
		}
		if _, found := hits[cdnIP.String()]; !found {
			hits[cdnIP.String()] = ratelimit.NewBucket(time.Duration(60)*time.Second, 20)
		}
		_, isSoonerThanMaxWait := hits[cdnIP.String()].TakeMaxDuration(1, 0)
		if !isSoonerThanMaxWait {
			fmt.Printf("IP %s over limit... ", cdnIP.String())
			if whitelist.contains(cdnIP) || whitelist.contains(clientIP) {
				fmt.Println("but is whitelisted so we don't care.")
			} else {
				fmt.Println("we should ban.")
			}
		}

	}
}
