package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/alienth/go-fastly"
	"github.com/juju/ratelimit"
)

type IPList struct {
	name string
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

type IPLists map[string]*IPList

func (l *IPList) contains(checkIP *net.IP) (bool, int) {
	if l == nil {
		return false, 0
	}
	for _, ip := range l.IPs {
		if ip.Equal(*checkIP) {
			return true, 32
		}
	}
	for _, net := range l.Nets {
		if net.Contains(*checkIP) {
			size, _ := net.IPNet.Mask.Size()
			return true, size
		}
	}

	return false, 0
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
	var maskSize int
	// Iterate through all of the lists and find the list with the most
	// specific match.
	for _, l := range lists {
		found, size := l.contains(ip)
		if found {
			if size > maskSize {
				maskSize = size
				ipList = l
			}
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

// getDimension takes in a service and a logEntry and spits out the Dimensions
// we want to bucket by for this IPList.
func (l *IPList) getDimension(log *logEntry, service *fastly.Service) *Dimension {
	switch l.DimensionType {
	case DimensionBackend:
		return &log.backend
	case DimensionFrontend:
		return &log.frontend
	case DimensionHost:
		return &log.host
	case DimensionService:
		return &Dimension{Type: l.DimensionType, Value: service.Name}
	}
	return &Dimension{}
}


