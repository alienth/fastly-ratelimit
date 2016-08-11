package main

import (
	"fmt"
	"net/http"
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
	fmt.Fprint(w, "<table><th>IP</th><th>Hits</th><th>Limited</th><th>Hits Per Sec</th>\n")

	var rates ipRates
	for _, ipr := range hitmap {
		rates = append(rates, ipr)
	}

	sort.Sort(hitsSortableIPRates{rates})
	for _, ipr := range rates {
		hps := float64(ipr.Hits) / time.Now().Sub(time.Unix(ipr.FirstHit, 0)).Seconds()
		if ipr.limited {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%d</td><td>%t</td><td>%f</td></tr>\n", ipr.ip.String(), ipr.Hits, ipr.limited, hps)
		}
	}
	fmt.Fprint(w, "</table>")
}
