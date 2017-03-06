package main

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/alienth/go-fastly"
	"github.com/juju/ratelimit"
)

type rateBucket struct {
	ratelimit.Bucket
	lastUsed time.Time
}

type ipRate struct {
	ip      *net.IP
	buckets map[Dimension]*rateBucket
	// Used to signal
	limited          bool
	shouldLimit      bool
	list             *IPList
	limitedOnService map[string]bool

	FirstHit    time.Time `json:"first_hit,omitempty"`
	LastHit     time.Time `json:"last_hit,omitempty"`
	LastLimit   time.Time `json:"last_limit,omitempty"`
	Hits        int       `json:"hits,omitempty"`
	Strikes     int       `json:"strikes,omitempty"`
	Expire      time.Time `json:"-"`
	LimitExpire time.Time `json:"limit_expire,omitempty"`

	sync.RWMutex
}

type ipRates []*ipRate
type hitsSortableIPRates struct{ ipRates }

func (r ipRates) Len() int                       { return len(r) }
func (r ipRates) Swap(i, j int)                  { r[i], r[j] = r[j], r[i] }
func (r hitsSortableIPRates) Less(i, j int) bool { return r.ipRates[i].Hits < r.ipRates[j].Hits }

type limitMessage struct {
	service   *fastly.Service
	ipRate    *ipRate
	operation fastly.BatchOperation
}

var limitCh = make(chan *limitMessage, 200)

func (ipr *ipRate) getAllBuckets() []rateBucket {
	ipr.RLock()
	defer ipr.RUnlock()

	buckets := make([]rateBucket, 0)

	if ipr.list.DimensionShared {
		sharedBuckets := ipr.list.sharedBuckets
		sharedBuckets.RLock()
		for _, bucket := range sharedBuckets.m {
			buckets = append(buckets, *bucket)
		}
		sharedBuckets.RUnlock()
	} else {
		for _, bucket := range ipr.buckets {
			buckets = append(buckets, *bucket)
		}
	}

	return buckets
}

func (ipr *ipRate) overAnyLimit() bool {
	buckets := ipr.getAllBuckets()

	for _, bucket := range buckets {
		if bucket.Available() < 0 {
			return true
		}
	}

	return false
}

// Initializes bucket if one doesn't already exist.
func (ipr *ipRate) getBucketByDimension(dimension *Dimension) *rateBucket {
	ipr.Lock()
	defer ipr.Unlock()

	var found bool
	// If DimensionValues were specified in our IPList, check to see if the
	// dimension passed matches that value. If it doesn't, zero out the
	// Dimension so that we just track by IP address.
	if len(ipr.list.DimensionValues) > 0 {
		for _, value := range ipr.list.DimensionValues {
			if value == dimension.Value {
				found = true
				break
			}
		}
		if found != true {
			dimension = &Dimension{}
		}
	}
	var bucket *rateBucket
	if *dimension != (Dimension{}) && ipr.list.DimensionShared {
		sharedBuckets := ipr.list.sharedBuckets
		sharedBuckets.Lock()
		if bucket, found = sharedBuckets.m[*dimension]; !found {
			bucket = &rateBucket{Bucket: *ratelimit.NewBucketWithQuantum(ipr.list.Time.Duration, ipr.list.Requests, ipr.list.Requests)}
			sharedBuckets.m[*dimension] = bucket
		}
		sharedBuckets.Unlock()
		ipr.buckets[*dimension] = bucket
	}
	if bucket, found = ipr.buckets[*dimension]; !found {
		bucket = &rateBucket{Bucket: *ratelimit.NewBucketWithQuantum(ipr.list.Time.Duration, ipr.list.Requests, ipr.list.Requests)}
		ipr.buckets[*dimension] = bucket
	}

	return bucket
}

// Records a hit and returns true if it is over limit.
func (ipr *ipRate) Hit(ts time.Time, dimension *Dimension) bool {
	bucket := ipr.getBucketByDimension(dimension)
	var overlimit bool
	waitTime := bucket.Take(1)
	bucket.lastUsed = ts
	if waitTime != 0 {
		overlimit = true
	}

	ipr.Lock()
	defer ipr.Unlock()
	if ipr.FirstHit.IsZero() {
		ipr.FirstHit = time.Now()
	}
	ipr.LastHit = ts
	ipr.Hits++
	ipr.Expire = time.Now().Add(ipr.list.Expire.Duration)
	return overlimit
}

// Limit adds an IP to a fastly edge ACL
func (ipr *ipRate) Limit(service *fastly.Service) error {
	// TODO address concurrent read
	if !noop && ipr.shouldLimit {
		msg := limitMessage{service: service, ipRate: ipr, operation: fastly.BatchOperationCreate}
		limitCh <- &msg
	}

	if noop && !ipr.limited {
		ipr.Lock()
		defer ipr.Unlock()
		// Pretend we limited here. Duplicates some of pushACLUpdates.
		ipr.Strikes++
		limitDuration := ipr.list.LimitDuration.multiply(float64(ipr.Strikes))
		ipr.LimitExpire = time.Now().Add(limitDuration.Duration)
		logger.Printf("NOOP: Would issue limit on IP %s on service %s, for duration of %v.\n", ipr.ip.String(), service.Name, limitDuration.Duration)
		// Pretend we're limited in noop mode so that messages don't spam.
		ipr.limited = true
	}

	return nil
}

const APIBulkLimit = 1000

// Processes the limitCh queue and fans out to separate service-specific
// channels, which are handled by individual processServiceQueue() goroutines.
// Also calls hook service, if applicable.
func queueFanout() {
	channelByService := make(map[*fastly.Service]chan *limitMessage)
	var ok bool

	for msg := range limitCh {
		var channel chan *limitMessage
		if channel, ok = channelByService[msg.service]; !ok {
			channelByService[msg.service] = make(chan *limitMessage, 200)
			channel = channelByService[msg.service]
			go processServiceQueue(msg.service, channel)
		}
		// Enqueue async to prevent downstream blocking from causing limitCh to pile up.
		go func(channel chan *limitMessage, msg *limitMessage) { channel <- msg }(channel, msg)
		// Call our webhooks, if they've been set.
		if msg.operation == fastly.BatchOperationCreate && hook.AddIPsUri != "" {
			go func(ip net.IP) {
				err := hook.Add(ip)
				if err != nil {
					logger.Println("Error calling webhook on IP addition for %s: %s\n", ip.String(), err)
				}
			}(*msg.ipRate.ip)
		} else if msg.operation == fastly.BatchOperationDelete && hook.RemoveIPsUri != "" {
			go func(ip net.IP) {
				err := hook.Remove(ip)
				if err != nil {
					logger.Println("Error calling webhook on IP removal for %s: %s\n", ip.String(), err)
				}
			}(*msg.ipRate.ip)
		}
	}
}

type ipOp struct {
	ip        string
	operation fastly.BatchOperation
}

type timestamp struct {
	mu sync.Mutex
	time.Time
}

var lastPush timestamp

// sync with pushACLUpdates to ensure we don't process a single service concurrenly.
func processServiceQueue(service *fastly.Service, channel chan *limitMessage) {
	interval := time.Duration(15 * time.Second)
	ticker := time.NewTicker(interval)

	batch := make([]*limitMessage, 0)

	ratesQueued := make(map[ipOp]bool)

	for {
		select {
		case msg := <-channel:
			key := ipOp{ip: msg.ipRate.ip.String(), operation: msg.operation}
			if !ratesQueued[key] {
				batch = append(batch, msg)
				ratesQueued[key] = true
				if len(batch)+20 >= APIBulkLimit || sendImmediately(interval) {
					pushACLUpdates(service, batch)
					batch = make([]*limitMessage, 0)
					ratesQueued = make(map[ipOp]bool)
				}
			}

		case _ = <-ticker.C:
			if len(batch) > 0 {
				pushACLUpdates(service, batch)
				batch = make([]*limitMessage, 0)
				ratesQueued = make(map[ipOp]bool)
			}
		}
	}

}

// pushACLUpdates takes a slice of *limitMessage and builds a slice of
// fastly.ACLEntryUpdate, and then calls fastly to execute those updates. It
// If a failure occurs along the way, it will requeue the batch messages into
// limitCh.
func pushACLUpdates(service *fastly.Service, batch []*limitMessage) {
	lastPush.mu.Lock()
	lastPush.Time = time.Now()
	lastPush.mu.Unlock()
	updates := make([]fastly.ACLEntryUpdate, 0)
	acl := aclByService[service]
	// Holds the ipRates which we need to update the entries for after
	// creating ACL entries.
	ratesToUpdate := make(ipRates, 0)

	// Used to track what iprates we're going to be creating, deleting, or
	// updating so that we don't try to double create or double delete.
	creating := make(map[*ipRate]bool)
	deleting := make(map[*ipRate]bool)
	updating := make(map[*ipRate]bool)

	entries, _, err := client.ACLEntry.List(service.ID, acl.ID)
	if err != nil {
		logger.Printf("Error fetching ACL Entry list for %s. Requeuing pending changes. Error: %s\n", service.Name, err)
		go requeueBatch(batch)
		return
	}

	for _, message := range batch {
		ipr := message.ipRate
		var existingEntry *fastly.ACLEntry
		for _, entry := range entries {
			// TODO handle cases where we are in the ACL multiple times?
			if entry.IP == ipr.ip.String() {
				existingEntry = entry
				break
			}
		}

		var update fastly.ACLEntryUpdate
		update.Operation = message.operation

		switch op := update.Operation; op {
		case fastly.BatchOperationDelete:
			if existingEntry == nil || deleting[ipr] {
				continue
			}
			logger.Printf("Unlimiting IP %s on service %s\n", ipr.ip.String(), service.Name)
			deleting[ipr] = true
			update.ID = existingEntry.ID
		case fastly.BatchOperationCreate:
			if existingEntry != nil || creating[ipr] {
				// someone else already updated it
				continue
			}
			creating[ipr] = true
			update.IP = ipr.ip.String()
		case fastly.BatchOperationUpdate:
			if existingEntry == nil {
				// someone else deleted it
				continue
			}
			updating[ipr] = true
			update.IP = ipr.ip.String()
			update.ID = existingEntry.ID
		}

		ipr.Lock()

		if update.Operation == fastly.BatchOperationCreate {
			if !ipr.limited {
				// Only increase the duration time if we're not already
				// limited.  This is because we might just be applying a limit
				// to a new service that we saw a hit on.
				// TODO change this - doesn't work well if we want to update a ban.
				//
				// Strikes should increment in the event that
				// they were banned, and then unbanned, and
				// then caused trouble again.
				ipr.Strikes++
			}

			limitDuration := ipr.list.LimitDuration.multiply(float64(ipr.Strikes))
			ipr.LimitExpire = time.Now().Add(limitDuration.Duration)
			logger.Printf("Limiting IP %s for %d minutes on service %s\n", ipr.ip.String(), int(limitDuration.Minutes()), service.Name)
			ipr.LastLimit = time.Now()
			ipr.Expire = time.Now().Add(time.Duration(24) * time.Hour)
		}

		if update.Operation != fastly.BatchOperationDelete {
			comment, err := json.Marshal(ipr)
			// This will probably never happen
			if err != nil {
				logger.Println("Unable to prepare update for %s on %s: %s", ipr.ip.String(), service.Name, err)
				continue
			}
			update.Comment = string(comment)
		}
		updates = append(updates, update)
		ratesToUpdate = append(ratesToUpdate, ipr)
		ipr.Unlock()
	}

	// This will happen if, for example, all of the iprates in the batch
	// were already present in the ACL. That can happen because the
	// mainloop might see more requests which push us over limit after the
	// IP has already been added to the acl, as the addition to the ACL has
	// some lag time.
	if len(updates) == 0 {
		return
	}

	if _, err := client.ACLEntry.BatchUpdate(service.ID, acl.ID, updates); err != nil {
		logger.Printf("Error updating ACL for %s. Requeuing pending changes. Error: %s\n", service.Name, err)
		go requeueBatch(batch)
	}

	// If this fails, then a RemoveLimit() call might assume an entry is
	// still in the ACL when it isn't. Not disasterous.
	if err = ratesToUpdate.syncWithACLEntries(service); err != nil {
		if err != nil {
			logger.Printf("Error syncing ip rates with ACL entries for service %s: %s\n", service.Name, err)
		}
	}

}

// Takes a batch of messages and sends em back to the limitCh
func requeueBatch(batch []*limitMessage) {
	for _, msg := range batch {
		limitCh <- msg
	}
}

// syncWithACLEntries operates on a set of ipRates. It takes a fastly service,
// lists the ACLEntries on that service, and then updates the ipRate's
// limitedOnService field based on the results from Fastly.
func (rates ipRates) syncWithACLEntries(service *fastly.Service) error {
	entries, _, err := client.ACLEntry.List(service.ID, aclByService[service].ID)
	if err != nil {
		return err
	}

	for _, ipr := range rates {
		ipr.Lock()
		found := false
		for _, entry := range entries {
			if entry.IP == ipr.ip.String() {
				found = true
				break
			}
		}
		if found {
			ipr.limitedOnService[service.ID] = true
			ipr.limited = true
		} else {
			ipr.limitedOnService[service.ID] = false
		}

		// See if we're limited by any services, and if not, signal
		// that this ip is no longer limited.
		if ipr.limited {
			found := false
			for _, limited := range ipr.limitedOnService {
				if limited {
					found = true
					break
				}
			}
			if !found {
				ipr.limited = false
			}
		}
		ipr.Unlock()
	}

	return nil
}

// sendImmediately checks our clients remaining API ratelimit. Takes a
// time.Duration as an indicator of the maximum amount of time we'd like to
// wait before sending. If the remaining time in the ratelimit divided by our
// maximum allowed duration is less than the remaining amount of actions in the
// ratelimit, return false as we lack the number of requests necessary to meet
// our guarantee.
// Also returns false if we already performed an API push within the last second.
func sendImmediately(guarantee time.Duration) bool {
	lastPush.mu.Lock()
	defer lastPush.mu.Unlock()
	if time.Now().Sub(lastPush.Time) < time.Duration(1)*time.Second {
		return false
	}
	rate := client.RateLimit()
	if rate == nil {
		// We don't know the current ratelimit.
		return false
	}

	if int(rate.Reset.Sub(time.Now())/guarantee) < rate.Remaining-20 {
		return false
	}

	return true
}

// Removes an IP from ratelimits
func (ipr *ipRate) RemoveLimit() {
	if !noop {
		ipr.RLock()
		for service, _ := range aclByService {
			if ipr.limitedOnService[service.ID] {
				msg := limitMessage{service: service, ipRate: ipr, operation: fastly.BatchOperationDelete}
				limitCh <- &msg
			}
		}
		ipr.RUnlock()
	}

	if noop {
		ipr.Lock()
		logger.Printf("NOOP: Would remove all limits for IP %s.\n", ipr.ip.String())
		ipr.limited = false
		ipr.Unlock()
	}

}

// clean will free any shared bucket from our IPList if this ipRate was the last
// to utilize that shared bucket.
func (ipr *ipRate) cleanSharedBuckets() {
	ipr.Lock()
	defer ipr.Unlock()
	sharedBuckets := ipr.list.sharedBuckets
	sharedBuckets.Lock()
	defer sharedBuckets.Unlock()
	for dimension, bucket := range ipr.buckets {
		if bucket.lastUsed == ipr.LastHit {
			delete(sharedBuckets.m, dimension)
		}
	}
}
