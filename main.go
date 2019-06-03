package main

import (
	"fmt"
	golog "log"
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
const workers = 1

var hits = hitMap{m: make(map[string]*ipRate)}

var logger = golog.New(os.Stdout, "", 0)

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
			Name:  "stats-listen, s",
			Usage: "Specify listen for web stats interface, `ADDRESS:PORT`.",
			Value: "0.0.0.0:80",
		},
		cli.StringFlag{
			Name:   "fastly-key, K",
			Usage:  "Fastly API Key. Can be read from 'fastly_key' file in CWD.",
			EnvVar: "FASTLY_KEY",
			Value:  util.GetFastlyKey(),
		},
		cli.StringFlag{
			Name:   "redis-channel, r",
			Usage:  "Redis Channel.",
			EnvVar: "REDIS_CHANNEL",
		},
		cli.StringFlag{
			Name:   "redis-address, a",
			Usage:  "Redis Address.",
			EnvVar: "REDIS_ADDRESS",
		},
		cli.BoolFlag{
			Name: "tcp, t",
			Usage: "Listens for syslog via TCP",
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

var config appConfig

func runServer(c *cli.Context) error {
	http.HandleFunc("/", handler)
	go func(listenAddr string) {
		if err := http.ListenAndServe(listenAddr, nil); err != nil {
			logger.Fatalf("Unable to start stats webserver: %s", err)
		}
	}(c.GlobalString("stats-listen"))
	client = fastly.NewClient(nil, c.GlobalString("fastly-key"))
	syslogChannel = make(syslog.LogPartsChannel, syslogChannelBufferSize)
	handler := syslog.NewChannelHandler(syslogChannel)

	syslogServer := syslog.NewServer()
	syslogServer.SetFormat(syslog.RFC3164)
	syslogServer.SetHandler(handler)

	var err error
	if c.GlobalBool("tcp") {
		err = syslogServer.ListenTCP(c.GlobalString("listen"))
	} else {
		err = syslogServer.ListenUDP(c.GlobalString("listen"))
	}

	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Unable to start syslog server: %s\n", err), -1)
	}

	noop = c.GlobalBool("noop")

	if config, err = readConfig(c.GlobalString("config")); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error reading config file:\n%s\n", err), -1)
	}
	ipLists = config.Lists
	hook = config.HookService

	// Override Redis channel and address if set in env var or by cli args
	if c.GlobalString("redis-channel") != "" {
		hook.RedisChannel = c.GlobalString("redis-channel")
	}

	if c.GlobalString("redis-address") != "" {
		hook.RedisAddr = c.GlobalString("redis-address")
	}

	hook.hookedIPs.m = make(map[string]bool)
	if err = hook.init(); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error setting up hooks:\n%s\n", err), -1)
	}

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

	if err := syslogServer.Boot(); err != nil {
		return cli.NewExitError(fmt.Sprintf("Unable to start syslog server: %s\n", err), -1)
	}

	for i := 1; i <= workers; i++ {
		go readLogs(syslogChannel, serviceDomains)
	}

	syslogServer.Wait()

	return nil
}

func readLogs(channel syslog.LogPartsChannel, serviceDomains ServiceDomains) {
	for logParts := range channel {
		var line string
		var ok bool
		if line, ok = logParts["content"].(string); !ok || line == "" {
			continue
		}
		log := config.logParser.parse(line)

		if log == nil || log.cdnIP == nil {
			continue
		}
		if time.Now().Sub(log.timestamp) > time.Duration(2)*time.Minute {
			logger.Printf("Warning: old log line. Log TS: %s, Current time: %s\n", log.timestamp.String(), time.Now().String())
		}
		var ipr *ipRate
		var found bool
		hits.Lock()
		if ipr, found = hits.m[log.cdnIP.String()]; !found {
			ipr = ipLists.getRate(log.cdnIP)
			hits.m[log.cdnIP.String()] = ipr
		}
		hits.Unlock()
		service, err := serviceDomains.getServiceByHost(log.host.Value)
		if err != nil {
			logger.Printf("Error while finding fastly service for domain %s: %s\n.", log.host.Value, err)
		}
		if service == nil {
			logger.Printf("Found request for host %s which is not in fastly. Ignoring\n", log.host.Value)
			continue
		}
		dimension := ipr.list.getDimension(log, service)
		overLimit := ipr.Hit(log.timestamp, dimension)
		if overLimit {
			if err := ipr.Limit(service); err != nil {
				logger.Printf("Error limiting IP: %s\n", err)
			}
		}

		if len(channel) == syslogChannelBufferSize {
			logger.Println("Warning: log buffer full. We are dropping logs.")
		}
	}

}
