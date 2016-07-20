package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/juju/ratelimit"
)

var logRegex = regexp.MustCompile("{.*?}")

// getIP takes in an haproxy log line and returns the IP contained in the 8th
// captured request header. In our case, that's the CDN-Connecting-IP header.
func getIP(logLine string) *net.IP {
	headers := strings.Split(string(logRegex.Find([]byte(logLine))), "|")
	if len(headers) < 7 {
		return nil
	}
	ipString := headers[7]
	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil
	}
	return &ip
}

func getLogTimestamp(logLine string) int64 {
	timestampStr := strings.Split(logLine, " ")[6]
	ts, _ := time.Parse("[02/Jan/2006:15:04:05.999]", timestampStr)

	return (ts.Unix())
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
	for scanner.Scan() {
		line := scanner.Text()
		ip := getIP(line)
		if ip == nil {
			continue
		}
		if _, found := hits[ip.String()]; !found {
			hits[ip.String()] = ratelimit.NewBucket(time.Duration(60)*time.Second, 200)
		}
		_, isSoonerThanMaxWait := hits[ip.String()].TakeMaxDuration(1, 0)
		if !isSoonerThanMaxWait {
			fmt.Printf("IP %s over limit\n", ip)
		}

	}
}
