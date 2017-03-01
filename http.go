package main

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sort"
	"time"
)

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

	rate := client.RateLimit()
	fmt.Fprintf(w, "<p>Alloc: %d, HeapObjects: %d</p>", m.Alloc, m.HeapObjects)
	fmt.Fprintf(w, "<p>Total IPs tracked: %d</p>", len(hits.m))
	if rate != nil {
		fmt.Fprintf(w, "<p>Fastly API ratelimit: %d calls remaining, reset in %v</p>", rate.Remaining, rate.Reset.Sub(time.Now()))
	}
	fmt.Fprint(w, "<h2>Limited IPs</h2>\n")
	fmt.Fprint(w, "<table><th>IP</th><th>Hits</th><th>Limited</th><th>HPS</th><th>Strikes</th><th>Limit Time Remaining</th><th>List</th>\n")

	var rates ipRates
	for _, ipr := range hitmap {
		rates = append(rates, ipr)
	}

	sort.Sort(sort.Reverse(hitsSortableIPRates{rates}))
	for _, ipr := range rates {
		hps := float64(ipr.Hits) / time.Now().Sub(ipr.FirstHit).Seconds()
		if ipr.limited {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%d</td><td>%t</td><td>%0.2f</td><td>%d</td><td>%0.2fm</td><td>%s</td></tr>\n", ipr.ip.String(), ipr.Hits, ipr.limited, hps, ipr.Strikes, ipr.LimitExpire.Sub(time.Now()).Minutes(), ipr.list.name)
		}
	}
	fmt.Fprint(w, "</table>")

	fmt.Fprint(w, "<h2>Top IPs</h2>\n")
	fmt.Fprint(w, "<table><th>IP</th><th>Hits</th><th>HPS</th><th>List</th>\n")
	for _, ipr := range rates {
		hps := float64(ipr.Hits) / time.Now().Sub(ipr.FirstHit).Seconds()
		if hps > 0.5 && ipr.Hits > 50 {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%d</td><td>%0.2f</td><td>%s</td></tr>\n", ipr.ip.String(), ipr.Hits, hps, ipr.list.name)
		}
	}
	fmt.Fprint(w, "</table>")

	fmt.Fprintf(w, "<h2>Top /24s</h2>\n")
	fmt.Fprint(w, "<table><th>Network</th><th>Hits</th><th>HPS</th><th>List</th>\n")
	ipRatesByNetwork := make(map[string][]*ipRate)
	mask := net.CIDRMask(24, 32)
	for _, ipr := range rates {
		iprIP := *ipr.ip
		ip := net.IPv4(iprIP[12], iprIP[13], iprIP[14], byte(0))
		network := net.IPNet{IP: ip, Mask: mask}
		ipRatesByNetwork[network.IP.String()] = append(ipRatesByNetwork[network.IP.String()], ipr)
	}
	var networks networkHPSs
	for network, rates := range ipRatesByNetwork {
		var totalHPS float64
		var totalHits int
		list := rates[0].list
		for _, ipr := range rates {
			hps := float64(ipr.Hits) / time.Now().Sub(ipr.FirstHit).Seconds()
			totalHPS += hps
			totalHits += ipr.Hits
			if ipr.list != list {
				list = nil
			}
		}
		if totalHits > 10000 || (totalHits > 100 && totalHPS > 1) {
			networks = append(networks, networkHPS{network: network, hps: totalHPS, hits: totalHits, list: list})
		}
	}
	sort.Sort(sort.Reverse(networks))
	for _, network := range networks {
		var list string
		if network.list != nil {
			list = network.list.name
		}
		fmt.Fprintf(w, "<tr><td><a href=\"https://stat.ripe.net/%s\">%s</a></td><td>%d</td><td>%0.2f</td><td>%s</td></tr>", network.network, network.network, network.hits, network.hps, list)
	}
	fmt.Fprint(w, "</table>")

	fmt.Fprint(w, "<h2>Traffic by list</h2>\n")
	fmt.Fprint(w, "<table><th>List</th><th>HPS</th><th>% of overall traffic</th>\n")

	var total float64
	l := make(map[*IPList]float64)
	for _, ipr := range rates {
		hps := float64(ipr.Hits) / time.Now().Sub(ipr.FirstHit).Seconds()
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

type networkHPS struct {
	network string
	hps     float64
	hits    int
	list    *IPList
}

type networkHPSs []networkHPS

func (l networkHPSs) Len() int           { return len(l) }
func (l networkHPSs) Less(i, j int) bool { return l[i].hits < l[j].hits }
func (l networkHPSs) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }
