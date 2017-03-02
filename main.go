package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/alienth/fastlyctl/util"
	"github.com/alienth/go-fastly"
	"github.com/urfave/cli"
	"gopkg.in/mcuadros/go-syslog.v2"

	_ "expvar"
	_ "net/http/pprof"
)

var client *fastly.Client
var ipLists IPLists
var hook hookService
var noop bool

var syslogChannel syslog.LogPartsChannel

// How many syslog logs we want to buffer, at max.
const syslogChannelBufferSize = 3000

// How many log reading workers we fire up
const workers = 2

// TODO pass this along in context to the webserver instead of
// making it global.
var hits = hitMap{m: make(map[string]*ipRate)}

func main() {
	app := cli.NewApp()
	app.Name = "fastly-ratelimit"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Usage: "Read config `FILE`.",
			Value: "config.toml",
		},
		cli.StringFlag{
			Name:  "listen, l",
			Usage: "Specify listen `ADDRESS:PORT`.",
			Value: "0.0.0.0:514",
		},
		cli.StringFlag{
			Name:   "fastly-key, K",
			Usage:  "Fastly API Key. Can be read from 'fastly_key' file in CWD.",
			EnvVar: "FASTLY_KEY",
			Value:  util.GetFastlyKey(),
		},
		cli.BoolFlag{
			Name:  "noop, n",
			Usage: "Noop mode. Print what we'd do, but don't actually do anything.",
		},
	}
	app.Before = func(c *cli.Context) error {
		if len(c.Args()) > 0 {
			return cli.NewExitError("Invalid usage. More arguments received than expected.", -1)
		}
		return nil
	}
	app.Action = runServer

	app.Run(os.Args)
}

func runServer(c *cli.Context) error {
	http.HandleFunc("/", handler)
	go http.ListenAndServe(":80", nil)
	client = fastly.NewClient(nil, c.GlobalString("fastly-key"))
	syslogChannel = make(syslog.LogPartsChannel, syslogChannelBufferSize)
	handler := syslog.NewChannelHandler(syslogChannel)

	noop = c.GlobalBool("noop")

	config, err := readConfig(c.GlobalString("config"))
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error reading config file:\n%s\n", err), -1)
	}
	ipLists = config.Lists
	hook = config.HookService
	hook.hookedIPs.m = make(map[string]bool)

	serviceDomains, err := getServiceDomains()
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Error fetching fasty domains:\n%s\n", err), -1)
	}

	if err := hits.importIPRates(serviceDomains); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error importing existing IP rates: %s", err), -1)
	}
	go hits.expireRecords()
	go hits.expireLimits()
	go queueFanout()
	if hook.SyncIPsUri != "" {
		go hits.syncIPsWithHook()
	}

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC3164)
	server.SetHandler(handler)
	if err := server.ListenUDP(c.GlobalString("listen")); err != nil {
		return cli.NewExitError(fmt.Sprintf("Unable to listen: %s\n", err), -1)
	}
	if err := server.Boot(); err != nil {
		return cli.NewExitError(fmt.Sprintf("Unable to start server: %s\n", err), -1)
	}

	for i := 1; i <= workers; i++ {
		go readLogs(syslogChannel, serviceDomains)
	}

	server.Wait()

	return nil
}

func readLogs(channel syslog.LogPartsChannel, serviceDomains ServiceDomains) {
	for logParts := range channel {
		var line string
		var ok bool
		if line, ok = logParts["content"].(string); !ok || line == "" {
			continue
		}
		log := parseLog(line)
		if log == nil || log.cdnIP == nil || log.clientIP == nil {
			continue
		}
		if time.Now().Sub(log.timestamp) > time.Duration(2)*time.Minute {
			fmt.Printf("Warning: old log line. Log TS: %s, Current time: %s\n", log.timestamp.String(), time.Now().String())
		}
		var ipr *ipRate
		var found bool
		ts := time.Now()
		hits.Lock()
		if d := ts.Sub(time.Now()); d > time.Duration(1)*time.Second {
			fmt.Printf("Blocked for %d seconds waiting for hits lock\n", int(d.Seconds()))
		}
		if ipr, found = hits.m[log.cdnIP.String()]; !found {
			ipr = ipLists.getRate(log.cdnIP)
			hits.m[log.cdnIP.String()] = ipr
		}
		hits.Unlock()
		service, err := serviceDomains.getServiceByHost(log.host.Value)
		if err != nil {
			fmt.Printf("Error while finding fastly service for domain %s: %s\n.", log.host.Value, err)
		}
		if service == nil {
			fmt.Printf("Found request for host %s which is not in fastly. Ignoring\n", log.host.Value)
			continue
		}
		dimension := ipr.list.getDimension(log, service)
		overLimit := ipr.Hit(log.timestamp, dimension)
		if overLimit {
			if err := ipr.Limit(service); err != nil {
				fmt.Printf("Error limiting IP: %s\n", err)
			}
		}

		if len(channel) == syslogChannelBufferSize {
			fmt.Println("Warning: log buffer full. We are dropping logs.")
		}
	}

}
