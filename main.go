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

	"github.com/BurntSushi/toml"
	"github.com/alienth/fastlyctl/util"
	"github.com/alienth/go-fastly"
	"github.com/juju/ratelimit"
	"github.com/urfave/cli"
	"gopkg.in/mcuadros/go-syslog.v2"
)

type logEntry struct {
	clientIP  *net.IP
	cdnIP     *net.IP
	host      string
	timestamp time.Time
}

// parseLog takes in an haproxy log line and returns a logEntry.
func parseLog(logLine string) *logEntry {
	var entry logEntry
	if logLine == "" {
		return nil
	}
	// This string parsing stuff was lifted from TPS
	var a, b int
	if a = strings.Index(logLine, "]:") + 3; a == -1 {
		return nil
	}
	if b = strings.Index(logLine[a:], ":"); b == -1 {
		return nil
	}
	clientIPString := logLine[a : a+b]
	clientIP := net.ParseIP(clientIPString)
	if clientIP == nil {
		return nil
	}
	entry.clientIP = &clientIP

	logLine = logLine[a+b:]
	// The subsequent square-bracketed string contains our timestamp
	if a = strings.Index(logLine, "[") + 1; a == -1 {
		return &entry
	}
	if b = strings.Index(logLine[a:], "]"); b == -1 {
		return &entry
	}
	timestampStr := logLine[a : a+b]
	entry.timestamp, _ = time.Parse("02/Jan/2006:15:04:05.999", timestampStr)

	logLine = logLine[a+b:]
	// The first curly-braced block contains our request headers
	if a = strings.Index(logLine, "{"); a == -1 {
		return &entry
	}
	if b = strings.Index(logLine[a:], "}"); b == -1 {
		return &entry
	}
	bracketedHeaders := logLine[a : a+b]
	headers := strings.Split(bracketedHeaders, "|")
	if len(headers) < 7 {
		return &entry
	}
	entry.host = headers[2]
	ipString := headers[7]
	cdnIP := net.ParseIP(ipString)
	if cdnIP == nil {
		return &entry
	}
	entry.cdnIP = &cdnIP
	return &entry
}

type duration struct {
	time.Duration
}

type ipNet struct {
	net.IPNet
}

type IPList struct {
	IPs  []*net.IP
	Nets []*ipNet

	Limit    bool
	Requests int64
	ListFile string

	Time          duration
	Expire        duration
	LimitDuration duration
}

func (d *duration) UnmarshalText(b []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(b))
	return err
}

// multiply takes in a factor and returns a new duration multiplied by that factor.
func (d duration) multiply(factor float64) duration {
	var newDuration duration
	newDuration.Duration = time.Duration(int(float64(d.Seconds())*factor)) * time.Second
	return newDuration
}

func (n *ipNet) UnmarshalText(b []byte) error {
	_, network, err := net.ParseCIDR(string(b))
	n.IPNet = *network
	return err
}

type IPLists map[string]*IPList

func readConfig(filename string) (IPLists, error) {
	ipLists := make(IPLists)

	if _, err := toml.DecodeFile(filename, &ipLists); err != nil {
		return nil, fmt.Errorf("toml parsing error: %s", err)
	}

	for _, list := range ipLists {
		if list.ListFile != "" {
			list.readListFile()
		}
	}

	return ipLists, nil
}

func (l *IPList) contains(checkIP *net.IP) bool {
	if l == nil {
		return false
	}
	for _, ip := range l.IPs {
		if ip.Equal(*checkIP) {
			return true
		}
	}
	for _, net := range l.Nets {
		if net.Contains(*checkIP) {
			return true
		}
	}

	return false
}

// readListFile reads a ListFile and parses the content
// into the IPLists' IPs and Nets fields.
func (l *IPList) readListFile() error {
	f, err := os.Open(l.ListFile)
	if err != nil {
		return err
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
			_, parsedNet, err := net.ParseCIDR(line)
			if err != nil {
				return fmt.Errorf("Unable to parse CIDR.\nLine:\n%s\nError:\n%s\n", line, err)
			}
			if parsedNet != nil {
				var n ipNet
				n.IP = parsedNet.IP
				n.Mask = parsedNet.Mask
				l.Nets = append(l.Nets, &n)
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				l.IPs = append(l.IPs, &ip)
			} else {
				return fmt.Errorf("Unable to parse IP address in list: %s\n", line)
			}
		}
	}

	return nil
}

func (lists IPLists) getRate(ip *net.IP) *ipRate {
	var ipr ipRate
	var ipList *IPList
	for _, ipList = range lists {
		if ipList.contains(ip) {
			break
		}
	}
	if ipList == nil {
		ipList = lists["_default_"]
	}

	ipr.bucket = ratelimit.NewBucket(ipList.Time.Duration, ipList.Requests)
	ipr.Expire = time.Now().Add(ipList.Expire.Duration).Unix()
	ipr.ip = ip
	ipr.shouldLimit = ipList.Limit
	ipr.list = ipList
	return &ipr
}

type ipRate struct {
	ip          *net.IP
	bucket      *ratelimit.Bucket
	entries     []*util.ACLEntry
	limited     bool
	shouldLimit bool
	list        *IPList

	FirstHit    int64 `json:"first_hit,omitempty"`
	LastHit     int64 `json:"last_hit,omitempty"`
	LastLimit   int64 `json:"last_limit,omitempty"`
	Hits        int   `json:"hits,omitempty"`
	Strikes     int   `json:"strikes,omitempty"`
	Expire      int64 `json:"-"`
	LimitExpire int64 `json:"limit_expire,omitempty"`

	sync.RWMutex
}

// Records a hit and returns true if it is over limit.
func (ipr *ipRate) Hit() bool {
	// Here we pretend that the IP performed no hits before the limit was removed,
	// since in testing the IP is not actually limited.
	if ipr.limited {
		return false
	}

	ipr.Lock()
	defer ipr.Unlock()
	_, isSoonerThanMaxWait := ipr.bucket.TakeMaxDuration(1, 0)
	if ipr.FirstHit == 0 {
		ipr.FirstHit = time.Now().Unix()
	}
	ipr.LastHit = time.Now().Unix()
	ipr.Hits++
	ipr.Expire = time.Now().Add(time.Duration(1) * time.Hour).Unix()
	return !isSoonerThanMaxWait
}

// Limit adds an IP to a fastly edge ACL
func (ipr *ipRate) Limit(serviceName string) error {
	if !ipr.shouldLimit {
		return nil
	}

	var entry *util.ACLEntry

	ipr.Lock()
	defer ipr.Unlock()

	ipr.LastLimit = time.Now().Unix()
	ipr.Strikes++
	limitDuration := ipr.list.LimitDuration.multiply(float64(ipr.Strikes))
	ipr.LimitExpire = time.Now().Add(limitDuration.Duration).Unix()
	fmt.Printf("Limit on %s will expire in %d minutes.\n", ipr.ip.String(), int(limitDuration.Minutes()))
	ipr.Expire = time.Now().Add(time.Duration(24) * time.Hour).Unix()
	comment, err := json.Marshal(ipr)
	if err != nil {
		return err
	}
	if entry == nil {
		entry, err = util.NewACLEntry(client, serviceName, "ratelimit", ipr.ip.String(), 0, string(comment), false)
		if err != nil {
			return err
		}
		fmt.Printf("Limiting IP %s\n", ipr.ip.String())
		if err = entry.Add(); err != nil {
			return err
		}
	} else {
		entry.Comment = string(comment)
		//		entry.Update()
	}

	ipr.limited = true
	ipr.entries = append(ipr.entries, entry)
	return nil
}

// Removes an IP from ratelimits
func (ipr *ipRate) RemoveLimit() error {
	ipr.Lock()
	defer ipr.Unlock()
	if len(ipr.entries) > 0 {
		fmt.Printf("Unlimiting IP %s\n", ipr.ip.String())
		for i, entry := range ipr.entries {
			if err := entry.Remove(); err != nil {
				return fmt.Errorf("Error removing limit for IP %s: %s", ipr.ip.String(), err)
			}
			ipr.entries[i] = nil
		}
		ipr.entries = ipr.entries[:0]
		ipr.limited = false
	}
	return nil
}

type hitMap struct {
	sync.RWMutex
	m map[string]*ipRate
}

// getMap returns a copy of the hitmap. This is used to prevent long lock times on the hitMap
func (hits *hitMap) getMap() map[string]*ipRate {
	newMap := make(map[string]*ipRate)
	hits.RLock()
	for ip, ipr := range hits.m {
		newMap[ip] = ipr
	}
	hits.RUnlock()
	return newMap
}

func (hits *hitMap) expireRecords() {
	for {
		hitMapCopy := hits.getMap()
		for ip, ipr := range hitMapCopy {
			ipr.Lock()
			if ipr.Expire < time.Now().Unix() {
				if err := ipr.RemoveLimit(); err != nil {
					fmt.Println(err)
				} else {
					hits.Lock()
					delete(hits.m, ip)
					hits.Unlock()
				}
			}
			ipr.Unlock()
		}
		time.Sleep(time.Duration(60) * time.Second)
	}
}

func (hits *hitMap) expireLimits() {
	for {
		hitMapCopy := hits.getMap()
		for _, ipr := range hitMapCopy {
			if ipr.LimitExpire < time.Now().Unix() {
				if err := ipr.RemoveLimit(); err != nil {
					fmt.Println(err)
				}
			}
		}
		time.Sleep(time.Duration(15) * time.Second)
	}
}

// Fetches down remote ACLs and populates local hitMap with previously stored data.
func (hits *hitMap) importIPRates() error {
	service, err := util.GetServiceByName(client, "stackoverflow.com")
	if err != nil {
		return err
	}

	acl, err := util.NewACL(client, service.Name, "ratelimit")
	if err != nil {
		return err
	}

	entries, err := acl.ListEntries()
	if err != nil {
		return err
	}

	// TODO: work with IPs existing in multiple services.
	for _, e := range entries {
		var ipr *ipRate
		var found bool
		hits.Lock()
		if ipr, found = hits.m[e.IP]; !found {
			ip := net.ParseIP(e.IP)
			ipr = ipLists.getRate(&ip)
			if ip == nil {
				return fmt.Errorf("Unable to parse IP %s in ACL.")
			}
			hits.m[ip.String()] = ipr
		}
		hits.Unlock()
		if err := json.Unmarshal([]byte(e.Comment), ipr); err != nil {
			break
		}
		entry := &util.ACLEntry{Client: client, ID: e.ID, ACLID: e.ACLID, ServiceID: service.ID}
		ipr.limited = true
		ipr.entries = append(ipr.entries, entry)
	}

	return nil
}

var client *fastly.Client
var ipLists IPLists

func main() {
	app := cli.NewApp()
	app.Name = "fastly-ratelimit"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Usage: "Read config `FILE`.",
			Value: "config.toml",
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
	app.ArgsUsage = "<SERVICE_NAME>"
	app.Before = func(c *cli.Context) error {
		if !c.Args().Present() {
			return cli.NewExitError("Please specify service.", -1)
		}
		if len(c.Args()) > 1 {
			return cli.NewExitError("Invalid usage. More arguments received than expected.", -1)
		}
		return nil
	}
	app.Action = func(c *cli.Context) error {
		client, _ = fastly.NewClient(c.GlobalString("fastly-key"))
		channel := make(syslog.LogPartsChannel)
		handler := syslog.NewChannelHandler(channel)

		var err error
		if ipLists, err = readConfig(c.GlobalString("config")); err != nil {
			return cli.NewExitError(fmt.Sprintf("Error reading config file:\n%s\n", err), -1)
		}

		serviceName := c.Args().Get(0)

		server := syslog.NewServer()
		server.SetFormat(syslog.RFC3164)
		server.SetHandler(handler)
		if err := server.ListenUDP(c.GlobalString("listen")); err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to listen: %s\n", err), -1)
		}
		if err := server.Boot(); err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to start server: %s\n", err), -1)
		}

		var hits = hitMap{m: make(map[string]*ipRate)}
		if err := hits.importIPRates(); err != nil {
			return cli.NewExitError(fmt.Sprintf("Error importing existing IP rates: %s", err), -1)
		}
		go hits.expireRecords()
		go hits.expireLimits()
		go func(channel syslog.LogPartsChannel) {
			for logParts := range channel {
				var line string
				var ok bool
				if line, ok = logParts["content"].(string); !ok || line == "" {
					continue
				}
				log := parseLog(line)
				if log == nil || log.cdnIP == nil || log.clientIP == nil {
					continue
				}
				if time.Now().Sub(log.timestamp) > time.Duration(2)*time.Minute {
					fmt.Printf("Warning: old log line. Log TS: %s, Current time: %s\n", log.timestamp.String(), time.Now().String())
				}
				var ipr *ipRate
				var found bool
				ts := time.Now()
				hits.Lock()
				if d := ts.Sub(time.Now()); d > time.Duration(1)*time.Second {
					fmt.Printf("Blocked for %s seconds waiting for hits lock\n", d.Seconds())
				}
				if ipr, found = hits.m[log.cdnIP.String()]; !found {
					ipr = ipLists.getRate(log.cdnIP)
					hits.m[log.cdnIP.String()] = ipr
				}
				hits.Unlock()
				overLimit := ipr.Hit()
				if overLimit {
					if ipr.shouldLimit {
						if err := ipr.Limit(serviceName); err != nil {
							fmt.Printf("Error limiting IP: %s", err)
						}
					} else {
						//fmt.Println("but is whitelisted so we don't care.")
					}
				}
			}
		}(channel)

		server.Wait()

		return nil
	}
	app.Run(os.Args)
}
