package main

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/alienth/go-fastly"
)

type hitMap struct {
	rwMutex
	m map[string]*ipRate
}

// GetMap returns a copy of the hitmap. This is used to prevent long lock times on the hitMap
func (hits *hitMap) GetMap() map[string]*ipRate {
	newMap := make(map[string]*ipRate)
	hits.RLock()
	for ip, ipr := range hits.m {
		newMap[ip] = ipr
	}
	hits.RUnlock()
	return newMap
}

func (hits *hitMap) ExpireRecords() {
	for {
		hitMapCopy := hits.GetMap()
		for ip, ipr := range hitMapCopy {

			ipr.RLock()
			expired := time.Now().After(ipr.Expire)
			limited := ipr.limited
			ipr.RUnlock()

			if expired {
				if limited {
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

func (hits *hitMap) ExpireLimits() {
	for {
		hitMapCopy := hits.GetMap()
		for _, ipr := range hitMapCopy {

			ipr.RLock()
			limitExpire := time.Now().After(ipr.LimitExpire)
			limited := ipr.limited
			ipr.RUnlock()

			if limited && limitExpire {
				ipr.RemoveLimit()
			}
		}
		time.Sleep(time.Duration(15) * time.Second)
	}
}

func (hits *hitMap) SyncIPsWithHook() {
	for {
		hitMapCopy := hits.GetMap()
		limits := make([]net.IP, 0)
		for _, ipr := range hitMapCopy {

			ipr.RLock()
			limited := ipr.limited
			shouldLimit := ipr.shouldLimit
			ipr.RUnlock()

			if limited || (shouldLimit && ipr.overAnyLimit()) {
				limits = append(limits, *ipr.ip)
			}
		}
		if !noop {
			if err := hook.Sync(limits); err != nil {
				logger.Printf("Error syncing banned IPs with hook service: %s\n", err)
			}
		}

		time.Sleep(time.Duration(10) * time.Minute)
	}
}

// Fetches down remote ACLs and populates local hitMap with previously stored data.
func (hits *hitMap) ImportIPRates(serviceDomains ServiceDomains) error {
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
				hits.Unlock()
				return fmt.Errorf("Unable to parse IP %s in ACL.", entry.IP)
			}
			hits.m[ip.String()] = ipr
		}
		hits.Unlock()

		var placeholder ipRate
		err := json.Unmarshal([]byte(entry.Comment), &placeholder)
		if err != nil {
			// We may not have created an entry, so ignore entries with
			// comments that we don't recognize.
			logger.Printf("Found unrecognized ACL comment for IP %s on service %s. Ignoring.\ncomment:\n%s\nError:\n%s\n", ipr.ip.String(), entry.ServiceID, entry.Comment, err)
			continue
		}

		ipr.Lock()
		if ipr.LastHit.Before(placeholder.LastHit) {
			json.Unmarshal([]byte(entry.Comment), &ipr)
		}
		ipr.limitedOnService[entry.ServiceID] = true
		ipr.limited = true
		ipr.Unlock()
	}

	return nil
}
