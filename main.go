package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	golog "log"

	"github.com/alienth/fastlyctl/util"
	"github.com/alienth/go-fastly"
	"github.com/urfave/cli"
	"gopkg.in/mcuadros/go-syslog.v2"

	_ "expvar"
	_ "net/http/pprof"
)

var (
	// Do not persist any changes
	noop = false
	// How many log reading workers we fire up
	workers = 1
	// How many syslog logs we want to buffer, at max.
	syslogChannelBufferSize = 3000

	client  *fastly.Client
	ipLists IPLists
	hook    hookService
	// Map of IP -> rate
	hits          = hitMap{m: make(map[string]*ipRate)}
	syslogChannel syslog.LogPartsChannel
	logger        = golog.New(os.Stdout, "", 0)
)

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
		cli.IntFlag{
			Name:        "log-workers, w",
			Usage:       "Number of log processing threads to spawn",
			EnvVar:      "LOG_WORKERS",
			Destination: &workers,
			Value:       workers,
		},
		cli.IntFlag{
			Name:        "syslog-buffer-size",
			Usage:       "Adjust the size of the syslog buffer",
			EnvVar:      "SYSLOG_BUFFER_SIZE",
			Destination: &syslogChannelBufferSize,
			Value:       syslogChannelBufferSize,
		},
		cli.BoolFlag{
			Name:  "tcp, t",
			Usage: "Listens for syslog via TCP",
		},
		cli.BoolFlag{
			Name:        "noop, n",
			Usage:       "Noop mode. Print what we'd do, but don't actually do anything.",
			Destination: &noop,
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
		logger.Printf("Listening at: %s", listenAddr)
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

	if err := hits.ImportIPRates(serviceDomains); err != nil {
		return cli.NewExitError(fmt.Sprintf("Error importing existing IP rates: %s", err), -1)
	}
	go hits.ExpireRecords()
	go hits.ExpireLimits()
	go queueFanout()
	if hook.SyncIPsUri != "" {
		go hits.SyncIPsWithHook()
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
		hits.RLock()
		ipr, found = hits.m[log.cdnIP.String()]
		hits.RUnlock()
		if !found {
			ipr = ipLists.getRate(log.cdnIP)
			hits.Lock()
			hits.m[log.cdnIP.String()] = ipr
			hits.Unlock()
		}
		service, err := serviceDomains.getServiceByHost(log.host.Value)
		if err != nil {
			logger.Printf("Error while finding fastly service for domain %s: %s\n.", log.host.Value, err)
		}
		if service == nil {
			logger.Printf("Found request for host %s which is not in fastly. Ignoring\n", log.host.Value)
			continue
		}

		// TODO move this to a method
		ipr.Lock()
		dimension := ipr.list.getDimension(log, service)
		ipr.Unlock()

		overLimit := ipr.Hit(log.timestamp, dimension)
		if overLimit {
			if err := ipr.Limit(service); err != nil {
				logger.Printf("Error limiting IP: %s\n", err)
			}
		}

		// We disable this message for environments with noop set because these are often debug environments. Debugging
		// tools tend to slow down execution and cause the binary to spew lines which can overwhelm logging agents or
		// make reading logs more difficult.
		if !noop && len(channel) == syslogChannelBufferSize {
			logger.Println("Warning: log buffer full. We are dropping logs.")
		}
	}

}
