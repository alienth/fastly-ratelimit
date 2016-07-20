package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hpcloud/tail"
)

// getIP takes in an haproxy log line and returns the IP contained in the 8th
// captured request header. In our case, that's the CDN-Connecting-IP header.
func getIP(logLine string) *net.IP {
	ipString := strings.Split(string(logRegex.Find([]byte(logLine))), "|")[7]
	ip := net.ParseIP(ipString)
	return &ip
}

func getLogTimestamp(logLine string) int64 {
	timestampStr := strings.Split(logLine, " ")[6]
	ts, _ := time.Parse("[02/Jan/2006:15:04:05.999]", timestampStr)

	return (ts.Unix())
}

func expireRecords(hits *hitMap) {
	for {
		hits.RLock()
		for ip, timestamps := range hits.m {
			for i, ts := range timestamps {
				if ts < time.Now().Unix()-600 {
					hits.m[ip] = append(timestamps[:i], timestamps[i+1:]...)
				}
			}
		}
		hits.RUnlock()
		hits.Lock()
		for ip, timestamps := range hits.m {
			if len(timestamps) == 0 {
				delete(hits.m, ip)
			}
		}
		hits.Unlock()
		time.Sleep(time.Duration(60))
	}
}

var logRegex *regexp.Regexp

type hitMap struct {
	sync.RWMutex
	m map[string][]int64
}

func main() {
	logRegex = regexp.MustCompile("{.*?}")
	t, err := tail.TailFile("/tmp/log", tail.Config{Follow: true})
	if err != nil {
		fmt.Println(err)
	}
	hits := hitMap{m: make(map[string][]int64)}
	go expireRecords(&hits)
	for line := range t.Lines {
		ip := getIP(line.Text).String()
		ts := getLogTimestamp(line.Text)
		hits.Lock()
		hits.m[ip] = append(hits.m[ip], ts)
		hits.Unlock()
	}
}
