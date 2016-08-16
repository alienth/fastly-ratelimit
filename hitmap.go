package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/alienth/fastlyctl/util"
)

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
