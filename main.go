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
)

var client *fastly.Client
var ipLists IPLists
var noop bool

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
	app.Action = func(c *cli.Context) error {
		http.HandleFunc("/", handler)
		go http.ListenAndServe(":80", nil)
		client = fastly.NewClient(nil, c.GlobalString("fastly-key"))
		channel := make(syslog.LogPartsChannel)
		handler := syslog.NewChannelHandler(channel)

		noop = c.GlobalBool("noop")

		var err error
		if ipLists, err = readConfig(c.GlobalString("config")); err != nil {
			return cli.NewExitError(fmt.Sprintf("Error reading config file:\n%s\n", err), -1)
		}

		serviceDomains, err := getServiceDomains()
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Error fetching fasty domains:\n%s\n", err), -1)
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

		if err := hits.importIPRates(serviceDomains); err != nil {
			return cli.NewExitError(fmt.Sprintf("Error importing existing IP rates: %s", err), -1)
		}
		go hits.expireRecords()
		go hits.expireLimits()
		go func(channel syslog.LogPartsChannel) {
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
					if ipr.shouldLimit {
						if err := ipr.Limit(service); err != nil {
							fmt.Printf("Error limiting IP: %s\n", err)
						}
					} else {
						//fmt.Println("but is whitelisted so we don't care.")
					}
				}
			}
		}(channel)

		server.Wait()

		return nil
	}
	app.Run(os.Args)
}
