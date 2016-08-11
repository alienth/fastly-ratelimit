package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
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

// The edge ACL which we will be interacting with in fastly.
const aclName = "ratelimit"

type logEntry struct {
	clientIP  *net.IP
	cdnIP     *net.IP
	host      string
	timestamp time.Time
	backend   Dimension
	frontend  Dimension
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
	// The subsequent string is our frontend
	if a = strings.Index(logLine, " ") + 1; a == -1 {
		return &entry
	}
	if b = strings.Index(logLine[a:], " "); b == -1 {
		return &entry
	}
	entry.frontend = Dimension{Type: DimensionFrontend, Value: logLine[a : a+b]}

	logLine = logLine[a+b:]
	// The subsequent string is our backend
	if a = strings.Index(logLine, " ") + 1; a == -1 {
		return &entry
	}
	if b = strings.Index(logLine[a:], "/"); b == -1 {
		return &entry
	}
	entry.backend = Dimension{Type: DimensionBackend, Value: logLine[a : a+b]}

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

	Limit         bool
	Requests      int64
	ListFile      string
	DimensionType DimensionType `toml:"Dimension"`

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
	for _, l := range lists {
		if l.contains(ip) {
			ipList = l
			break
		}
	}
	if ipList == nil {
		ipList = lists["_default_"]
	}

	ipr.buckets = make(map[Dimension]*ratelimit.Bucket)
	ipr.Expire = time.Now().Add(ipList.Expire.Duration).Unix()
	ipr.ip = ip
	ipr.shouldLimit = ipList.Limit
	ipr.list = ipList
	return &ipr
}

// getDimension takes in a logEntry and spits out the Dimensions we
// want to bucket by for this IPList.
func (l *IPList) getDimension(log *logEntry) *Dimension {
	switch l.DimensionType {
	case DimensionBackend:
		return &log.backend
	case DimensionFrontend:
		return &log.frontend
	}
	return &Dimension{Type: DimensionNone}
}

type DimensionType int

const (
	DimensionNone DimensionType = 1 << iota
	DimensionBackend
	DimensionFrontend
)

func (t *DimensionType) UnmarshalText(b []byte) error {
	s := string(b)
	switch s {
	case "backend":
		*t = DimensionBackend
	case "frontend":
		*t = DimensionFrontend
	default:
		return fmt.Errorf("Unrecognized dimension type %s\n", s)
	}
	return nil
}

type Dimension struct {
	Type  DimensionType
	Value string
}

type ipRate struct {
	ip          *net.IP
	buckets     map[Dimension]*ratelimit.Bucket
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
func (ipr *ipRate) Hit(dimension *Dimension) bool {
	ipr.Lock()
	defer ipr.Unlock()
	if _, found := ipr.buckets[*dimension]; !found {
		rate := float64(ipr.list.Requests) / ipr.list.Time.Duration.Seconds()
		ipr.buckets[*dimension] = ratelimit.NewBucketWithRate(rate, ipr.list.Requests)
	}
	var overlimit bool
	waitTime := ipr.buckets[*dimension].Take(1)
	if waitTime != 0 {
		overlimit = true
	}
	if ipr.FirstHit == 0 {
		ipr.FirstHit = time.Now().Unix()
	}
	ipr.LastHit = time.Now().Unix()
	ipr.Hits++
	ipr.Expire = time.Now().Add(time.Duration(1) * time.Hour).Unix()
	return overlimit
}

// Limit adds an IP to a fastly edge ACL
func (ipr *ipRate) Limit(service *fastly.Service) error {
	ipr.Lock()
	defer ipr.Unlock()

	if !ipr.shouldLimit {
		return nil
	}

	// Return if this IP is already limited on this service.
	for _, e := range ipr.entries {
		if e.ServiceID == service.ID {
			return nil
		}
	}

	ipr.LastLimit = time.Now().Unix()
	if !ipr.limited {
		// Only increase the duration time if we're not already
		// limited.  This is because we might just be applying a limit
		// to a new service that we saw a hit on.
		ipr.Strikes++
	}
	limitDuration := ipr.list.LimitDuration.multiply(float64(ipr.Strikes))
	ipr.LimitExpire = time.Now().Add(limitDuration.Duration).Unix()
	ipr.Expire = time.Now().Add(time.Duration(24) * time.Hour).Unix()
	comment, err := json.Marshal(ipr)
	if err != nil {
		return err
	}
	entry, err := util.NewACLEntry(client, service.Name, aclName, ipr.ip.String(), 0, string(comment), false)
	if err != nil {
		return err
	}
	fmt.Printf("Limiting IP %s for %d minutes on service %s\n", ipr.ip.String(), int(limitDuration.Minutes()), service.Name)
	if !noop {
		if err = entry.Add(); err != nil {
			return err
		}
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
		// defer the filtration in case we get an error during the removal loop
		defer func(ipr *ipRate) {
			newEntries := ipr.entries[:0]
			for _, e := range ipr.entries {
				if e != nil {
					newEntries = append(newEntries, e)
				}
			}
			ipr.entries = newEntries
		}(ipr)
		for i, entry := range ipr.entries {
			if !noop {
				if err := entry.Remove(); err != nil {
					return fmt.Errorf("Error removing limit for IP %s: %s", ipr.ip.String(), err)
				}
			}
			ipr.entries[i] = nil
		}
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
			if ipr.Expire < time.Now().Unix() {
				if err := ipr.RemoveLimit(); err != nil {
					fmt.Println(err)
				} else {
					hits.Lock()
					delete(hits.m, ip)
					hits.Unlock()
				}
			}
		}
		hitMapCopy = nil
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
func (hits *hitMap) importIPRates(serviceDomains ServiceDomains) error {
	aclEntries := make([]*util.ACLEntry, 0)
	for service, _ := range serviceDomains {
		acl, err := util.NewACL(client, service.Name, aclName)
		if err != nil {
			return err
		}

		entries, err := acl.ListEntries()
		if err != nil {
			return err
		}

		for _, e := range entries {
			entry := &util.ACLEntry{Client: client, ID: e.ID, ACLID: e.ACLID, ServiceID: service.ID, IP: e.IP, Comment: e.Comment, Subnet: e.Subnet, Negated: e.Negated}
			aclEntries = append(aclEntries, entry)
		}
	}
	for _, entry := range aclEntries {
		var ipr *ipRate
		var found bool
		hits.Lock()
		if ipr, found = hits.m[entry.IP]; !found {
			ip := net.ParseIP(entry.IP)
			ipr = ipLists.getRate(&ip)
			if ip == nil {
				return fmt.Errorf("Unable to parse IP %s in ACL.")
			}
			hits.m[ip.String()] = ipr
		}
		hits.Unlock()

		var placeholder ipRate
		err := json.Unmarshal([]byte(entry.Comment), &placeholder)
		if err != nil {
			// We may not have created an entry, so ignore entries with
			// comments that we don't recognize.
			break
		}
		if ipr.LastHit < placeholder.LastHit {
			json.Unmarshal([]byte(entry.Comment), &ipr)
		}
		ipr.limited = true
		ipr.entries = append(ipr.entries, entry)
	}

	return nil
}

type ServiceDomains map[*fastly.Service][]fastly.Domain

func getServiceDomains() (ServiceDomains, error) {
	serviceDomains := make(ServiceDomains)

	services, err := client.ListServices(&fastly.ListServicesInput{})
	if err != nil {
		return nil, err
	}

	for _, s := range services {
		var i fastly.ListDomainsInput
		i.Service = s.ID
		i.Version = strconv.Itoa(int(s.ActiveVersion))
		domains, err := client.ListDomains(&i)
		if err != nil {
			return nil, err
		}

		var x fastly.ListACLsInput
		x.Service = s.ID
		x.Version = strconv.Itoa(int(s.ActiveVersion))
		acls, err := client.ListACLs(&x)
		if err != nil {
			return nil, err
		}
		var found bool
		for _, acl := range acls {
			if acl.Name == aclName {
				found = true
				break
			}
		}
		if found {
			for _, d := range domains {
				serviceDomains[s] = append(serviceDomains[s], *d)
			}
		}
	}
	return serviceDomains, nil
}

// getServiceByHost takes in a hostname and returns the faslty service
// associated with that hostname.
func (services ServiceDomains) getServiceByHost(hostname string) (*fastly.Service, error) {
	for s, domains := range services {
		for _, d := range domains {
			if d.Name == hostname {
				return s, nil
			}
		}
		for _, d := range domains {
			// The fastly hostname can contain wildcard records such as
			// *.stackoverflow.com. We use path.Match() to match on those.
			// A specific domain will override a wildcard, which is why
			// we're doing this in a second loop.
			found, err := path.Match(d.Name, strings.ToLower(hostname))
			if err != nil {
				// only possible error here would be a malformed pattern
				return nil, err
			}
			if found {
				return s, nil
			}
		}
	}

	return nil, nil
}

var client *fastly.Client
var ipLists IPLists
var noop bool
// TODO pass this along in context to the webserver instead of
// making it global.
var hits = hitMap{m: make(map[string]*ipRate)}

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
		cli.BoolFlag{
			Name:  "noop, n",
			Usage: "Noop mode. Print what we'd do, but don't actually do anything.",
		},
	}
	app.Before = func(c *cli.Context) error {
		if len(c.Args()) > 0 {
			return cli.NewExitError("Invalid usage. More arguments received than expected.", -1)
		}
		return nil
	}
	app.Action = func(c *cli.Context) error {
		http.HandleFunc("/", handler)
		go http.ListenAndServe(":80", nil)
		client, _ = fastly.NewClient(c.GlobalString("fastly-key"))
		channel := make(syslog.LogPartsChannel)
		handler := syslog.NewChannelHandler(channel)

		noop = c.GlobalBool("noop")

		var err error
		if ipLists, err = readConfig(c.GlobalString("config")); err != nil {
			return cli.NewExitError(fmt.Sprintf("Error reading config file:\n%s\n", err), -1)
		}

		serviceDomains, err := getServiceDomains()
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Error fetching fasty domains:\n%s\n", err), -1)
		}

		server := syslog.NewServer()
		server.SetFormat(syslog.RFC3164)
		server.SetHandler(handler)
		if err := server.ListenUDP(c.GlobalString("listen")); err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to listen: %s\n", err), -1)
		}
		if err := server.Boot(); err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to start server: %s\n", err), -1)
		}

		if err := hits.importIPRates(serviceDomains); err != nil {
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
					fmt.Printf("Blocked for %d seconds waiting for hits lock\n", int(d.Seconds()))
				}
				if ipr, found = hits.m[log.cdnIP.String()]; !found {
					ipr = ipLists.getRate(log.cdnIP)
					hits.m[log.cdnIP.String()] = ipr
				}
				hits.Unlock()
				dimension := ipr.list.getDimension(log)
				overLimit := ipr.Hit(dimension)
				service, err := serviceDomains.getServiceByHost(log.host)
				if err != nil {
					fmt.Printf("Error while finding fastly service for domain %s: %s\n.", log.host, err)
				}
				if service == nil {
					fmt.Printf("Found request for host %s which is not in fastly. Ignoring\n", log.host)
					continue
				}
				if overLimit {
					if ipr.shouldLimit {
						if err := ipr.Limit(service); err != nil {
							fmt.Printf("Error limiting IP: %s\n", err)
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
