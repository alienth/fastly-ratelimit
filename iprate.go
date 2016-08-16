package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/alienth/fastlyctl/util"
	"github.com/alienth/go-fastly"
	"github.com/juju/ratelimit"
)

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
	ipr.Expire = time.Now().Add(ipr.list.Expire.Duration).Unix()
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
