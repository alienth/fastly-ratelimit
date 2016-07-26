package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alienth/fastlyctl/util"
	"github.com/alienth/go-fastly"
	"github.com/juju/ratelimit"
	"github.com/urfave/cli"
	"gopkg.in/mcuadros/go-syslog.v2"
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

func readIPList(filename string) (*ipList, error) {
	var list ipList
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
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
				return nil, fmt.Errorf("Unable to parse CIDR.\nLine:\n%s\nError:\n%s\n", line, err)
			}
			if n != nil {
				list.nets = append(list.nets, *n)
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				list.ips = append(list.ips, ip)
			} else {
				return nil, fmt.Errorf("Unable to parse IP address in list: %s\n", line)
			}
		}

	}
	return &list, nil
}

func (l *ipList) contains(checkIP *net.IP) bool {
	if l == nil {
		return false
	}
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

type ipRate struct {
	ip      *net.IP
	bucket  *ratelimit.Bucket
	entries []*util.ACLEntry

	FirstHit    int64 `json:"first_hit,omitempty"`
	LastHit     int64 `json:"last_hit,omitempty"`
	LastLimit   int64 `json:"last_limit,omitempty"`
	Hits        int   `json:"hits,omitempty"`
	Strikes     int   `json:"strikes,omitempty"`
	Expire      int64 `json:"-"`
	LimitExpire int64 `json:"limit_expire,omitempty"`
}

func (ipr *ipRate) New(ip *net.IP) {
	ipr.ip = ip
	ipr.bucket = ratelimit.NewBucket(time.Duration(3)*time.Minute, 180)
	ipr.Expire = time.Now().Add(time.Duration(1) * time.Hour).Unix()
}

// Records a hit and returns true if it is over limit.
func (ipr *ipRate) Hit() bool {
	_, isSoonerThanMaxWait := ipr.bucket.TakeMaxDuration(1, 0)
	if ipr.FirstHit == 0 {
		ipr.FirstHit = time.Now().Unix()
	}
	ipr.LastHit = time.Now().Unix()
	ipr.Expire = time.Now().Add(time.Duration(1) * time.Hour).Unix()
	return isSoonerThanMaxWait
}

// Limit adds an IP to a fastly edge ACL
func (ipr *ipRate) Limit() error {

	// remove me
	if time.Now().Unix()-ipr.LastLimit < 3600 {
		return nil
	}

	service, err := util.GetServiceByNameOrID(client, "teststackoverflow.com")
	if err != nil {
		return err
	}

	acl, err := util.NewACL(client, service.ID, "ratelimit")
	if err != nil {
		return err
	}

	// TODO this is heavy.. cache? do we even need?(see below)
	entries, err := acl.ListEntries()
	if err != nil {
		return err
	}

	// TODO This won't typically happen in normal conditions.. should we care?
	for _, e := range entries {
		if ipr.ip.String() == e.IP {
			fmt.Printf("IP %s is already limited.\n", e.IP)
			json.Unmarshal([]byte(e.Comment), ipr)
			ipr.LastLimit = time.Now().Unix()
			ipr.Strikes += 1
			ipr.Expire = time.Now().Add(time.Duration(24) * time.Hour).Unix()
			comment, err := json.Marshal(ipr)
			if err != nil {
				return err
			}
			entry := &util.ACLEntry{Client: client, ID: e.ID, ACLID: e.ACLID, ServiceID: service.ID, Comment: string(comment)}
			ipr.entries = append(ipr.entries, entry)
			// TODO: Update the entry?
			return nil
		}
	}

	fmt.Printf("Limiting IP %s\n", ipr.ip.String())
	ipr.LastLimit = time.Now().Unix()
	ipr.Strikes += 1
	ipr.LimitExpire = time.Now().Add(time.Duration(5) * time.Minute).Unix()
	ipr.Expire = time.Now().Add(time.Duration(24) * time.Hour).Unix()
	comment, err := json.Marshal(ipr)
	if err != nil {
		return err
	}
	entry, err := util.NewACLEntry(client, service.ID, "ratelimit", ipr.ip.String(), 0, string(comment), false)
	if err != nil {
		return err
	}
	entry.Add()
	ipr.entries = append(ipr.entries, entry)
	return nil
}

// Removes an IP from ratelimits
func (ipr *ipRate) RemoveLimit() error {
	if len(ipr.entries) > 0 {
		fmt.Printf("Unlimiting IP %s\n", ipr.ip.String())
		for i, entry := range ipr.entries {
			entry.Remove()
			ipr.entries[i] = nil
		}
		ipr.entries = ipr.entries[:0]
	}
	return nil
}

type hitMap struct {
	sync.RWMutex
	m map[string]*ipRate
}

func expireRecords(hits *hitMap) {
	for {
		hits.Lock()
		for ip, ipr := range hits.m {
			if ipr.Expire < time.Now().Unix() {
				ipr.RemoveLimit()
				delete(hits.m, ip)
			}
		}
		hits.Unlock()
		time.Sleep(time.Duration(60) * time.Second)
	}
}

func expireLimits(hits *hitMap) {
	for {
		hits.Lock()
		for _, ipr := range hits.m {
			if ipr.LimitExpire < time.Now().Unix() {
				ipr.RemoveLimit()
			}
		}
		hits.Unlock()
		time.Sleep(time.Duration(15) * time.Second)
	}
}

var client *fastly.Client

func main() {
	app := cli.NewApp()
	app.Name = "fastly-ratelimit"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "whitelist, w",
			Usage: "Read `FILE` containing addresses which should whitelisted from any bans.",
		},
		cli.StringFlag{
			Name:  "listen, l",
			Usage: "Specify listen `ADDRESS:PORT`.",
			Value: "0.0.0.0:514",
		},
		cli.StringFlag{
			Name:   "fastly-key, K",
			Usage:  "Fastly API Key. Can be read from 'fastly_key' file in CWD.",
			EnvVar: "FASTLY_KEY",
			Value:  util.GetFastlyKey(),
		},
	}
	app.Action = func(c *cli.Context) error {
		client, _ = fastly.NewClient(c.GlobalString("fastly-key"))
		channel := make(syslog.LogPartsChannel)
		handler := syslog.NewChannelHandler(channel)

		server := syslog.NewServer()
		server.SetFormat(syslog.RFC3164)
		server.SetHandler(handler)
		if err := server.ListenUDP(c.GlobalString("listen")); err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to listen: %s\n", err), -1)
		}
		if err := server.Boot(); err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to start server: %s\n", err), -1)
		}

		var whitelist *ipList
		var err error
		whitelistFile := c.GlobalString("whitelist")
		if whitelistFile != "" {
			if whitelist, err = readIPList(whitelistFile); err != nil {
				return cli.NewExitError(fmt.Sprintf("Error reading whitelist file: %s", err), -1)
			}
		}

		var hits = hitMap{m: make(map[string]*ipRate)}
		go expireRecords(&hits)
		go expireLimits(&hits)
		go func(channel syslog.LogPartsChannel) {
			for logParts := range channel {
				var line string
				var ok bool
				if line, ok = logParts["content"].(string); !ok || line == "" {
					continue
				}
				clientIP, cdnIP := getIPs(line)
				if cdnIP == nil || clientIP == nil {
					continue
				}
				var ipr *ipRate
				var found bool
				hits.Lock()
				if ipr, found = hits.m[cdnIP.String()]; !found {
					ipr = &ipRate{}
					ipr.New(cdnIP)
					hits.m[cdnIP.String()] = ipr
				}
				hits.Unlock()
				overLimit := ipr.Hit()
				if !overLimit {
					if whitelist.contains(cdnIP) {
						//fmt.Println("but is whitelisted so we don't care.")
					} else {
						if err := ipr.Limit(); err != nil {
							fmt.Printf("Error limiting IP: %s", err)
						}
					}
				}
			}
		}(channel)

		server.Wait()

		return nil
	}
	app.Run(os.Args)
}
