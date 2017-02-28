package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/alienth/go-fastly"
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
			if time.Now().After(ipr.Expire) {
				if ipr.limited {
					ipr.RemoveLimit()
				}
				hits.Lock()
				delete(hits.m, ip)
				hits.Unlock()
				ipr.cleanSharedBuckets()
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
			if ipr.limited && time.Now().After(ipr.LimitExpire) {
				ipr.RemoveLimit()
			}
		}
		time.Sleep(time.Duration(15) * time.Second)
	}
}

func (hits *hitMap) syncIPsWithHook(hook hookService) {
	for {
		hitMapCopy := hits.getMap()
		limits := make([]net.IP, 0)
		for _, ipr := range hitMapCopy {
			if ipr.limited {
				limits = append(limits, *ipr.ip)
			}
		}
		if err := hook.Sync(limits); err != nil {
			fmt.Printf("Error syncing banned IPs with hook service: %s\n", err)
		}

		time.Sleep(time.Duration(10) * time.Minute)
	}
}

// Fetches down remote ACLs and populates local hitMap with previously stored data.
func (hits *hitMap) importIPRates(serviceDomains ServiceDomains) error {
	aclEntries := make([]*fastly.ACLEntry, 0)
	for service, _ := range serviceDomains {
		acl, _, err := client.ACL.Get(service.ID, service.Version, aclName)
		if err != nil {
			return err
		}

		entries, _, err := client.ACLEntry.List(service.ID, acl.ID)
		if err != nil {
			return err
		}

		for _, e := range entries {
			aclEntries = append(aclEntries, e)
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
			fmt.Printf("Found unrecognized ACL comment for IP %s on service %s. Ignoring.\ncomment:\n%s\nError:\n%s\n", ipr.ip.String(), entry.ServiceID, entry.Comment, err)
			continue
		}
		if ipr.LastHit.Before(placeholder.LastHit) {
			json.Unmarshal([]byte(entry.Comment), &ipr)
		}
		ipr.limitedOnService[entry.ServiceID] = true
		ipr.limited = true
	}

	return nil
}
