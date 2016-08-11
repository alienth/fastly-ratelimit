package main

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"time"
)

type ipRates []*ipRate
type hitsSortableIPRates struct{ ipRates }

func (r ipRates) Len() int                       { return len(r) }
func (r ipRates) Swap(i, j int)                  { r[i], r[j] = r[j], r[i] }
func (r hitsSortableIPRates) Less(i, j int) bool { return r.ipRates[i].Hits < r.ipRates[j].Hits }

func handler(w http.ResponseWriter, r *http.Request) {
	hitmap := hits.getMap()
	if noop {
		fmt.Fprintf(w, "<h1>In noop mode</h1>\n")
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Fprintf(w, "<p>Alloc: %d, HeapObjects: %d</p>", m.Alloc, m.HeapObjects)
	fmt.Fprintf(w, "<p>Total IPs tracked: %d</p>", len(hits.m))
	fmt.Fprint(w, "<table><th>IP</th><th>Hits</th><th>Limited</th><th>HPS</th><th>Strikes</th><th>Limit Time Remaining</th>\n")

	var rates ipRates
	for _, ipr := range hitmap {
		rates = append(rates, ipr)
	}

	sort.Sort(hitsSortableIPRates{rates})
	for _, ipr := range rates {
		hps := float64(ipr.Hits) / time.Now().Sub(time.Unix(ipr.FirstHit, 0)).Seconds()
		if ipr.limited {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%d</td><td>%t</td><td>%0.2f</td><td>%d</td><td>%0.2fm</td></tr>\n", ipr.ip.String(), ipr.Hits, ipr.limited, hps, ipr.Strikes, time.Unix(ipr.LimitExpire, 0).Sub(time.Now()).Minutes())
		}
	}
	fmt.Fprint(w, "</table>")
}
