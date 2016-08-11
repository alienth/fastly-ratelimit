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

func header() string {
	return `
<!DOCTYPE html>
<html>
<head>
<style>
table, th, td {
        border: 1px solid black;
        border-collapse: collapse;
}
</style>
</head>
<body>
`
}

func handler(w http.ResponseWriter, r *http.Request) {
	hitmap := hits.getMap()
	if noop {
		fmt.Fprintf(w, "<h1>In noop mode</h1>\n")
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	fmt.Fprint(w, header())

	fmt.Fprintf(w, "<p>Alloc: %d, HeapObjects: %d</p>", m.Alloc, m.HeapObjects)
	fmt.Fprintf(w, "<p>Total IPs tracked: %d</p>", len(hits.m))
	fmt.Fprint(w, "<h2>Limited IPs</h2>\n")
	fmt.Fprint(w, "<table><th>IP</th><th>Hits</th><th>Limited</th><th>HPS</th><th>Strikes</th><th>Limit Time Remaining</th>\n")

	var rates ipRates
	for _, ipr := range hitmap {
		rates = append(rates, ipr)
	}

	sort.Sort(sort.Reverse(hitsSortableIPRates{rates}))
	for _, ipr := range rates {
		hps := float64(ipr.Hits) / time.Now().Sub(time.Unix(ipr.FirstHit, 0)).Seconds()
		if ipr.limited {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%d</td><td>%t</td><td>%0.2f</td><td>%d</td><td>%0.2fm</td></tr>\n", ipr.ip.String(), ipr.Hits, ipr.limited, hps, ipr.Strikes, time.Unix(ipr.LimitExpire, 0).Sub(time.Now()).Minutes())
		}
	}
	fmt.Fprint(w, "</table>")

	fmt.Fprint(w, "<h2>Whitelisted IPs</h2>\n")
	fmt.Fprint(w, "<table><th>IP</th><th>Hits</th><th>HPS</th><th>List</th>\n")
	for _, ipr := range rates {
		hps := float64(ipr.Hits) / time.Now().Sub(time.Unix(ipr.FirstHit, 0)).Seconds()
		if !ipr.shouldLimit && hps > 0.5 {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%d</td><td>%0.2f</td><td>%s</td></tr>\n", ipr.ip.String(), ipr.Hits, hps, ipr.list.name)
		}
	}
	fmt.Fprint(w, "</table>")

	fmt.Fprint(w, "<h2>Traffic by list</h2>\n")
	fmt.Fprint(w, "<table><th>List</th><th>HPS</th><th>% of overall traffic</th>\n")

	var total float64
	l := make(map[*IPList]float64)
	for _, ipr := range rates {
		hps := float64(ipr.Hits) / time.Now().Sub(time.Unix(ipr.FirstHit, 0)).Seconds()
		l[ipr.list] += hps
		total += hps
	}
	var lists listHPSs
	for iplist, hps := range l {
		lists = append(lists, listHPS{list: iplist, hps: hps})
	}
	sort.Sort(sort.Reverse(lists))
	for _, list := range lists {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%0.2f</td><td>%0.1f%%</tr>\n", list.list.name, list.hps, (list.hps/total)*100)
	}
	fmt.Fprint(w, "</table>")
}

type listHPS struct {
	list *IPList
	hps  float64
}

type listHPSs []listHPS

func (l listHPSs) Len() int           { return len(l) }
func (l listHPSs) Less(i, j int) bool { return l[i].hps < l[j].hps }
func (l listHPSs) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }
