package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/juju/ratelimit"
	"github.com/urfave/cli"
	"gopkg.in/mcuadros/go-syslog.v2"
)

// getIPs takes in an haproxy log line and returns the client IP and the CDN
// connecting IP which is in the captured request header. For us, the CDN
// connecting IP happens to be the 8th captured request header.
func getIPs(logLine string) (*net.IP, *net.IP) {
	if logLine == "" {
		return nil, nil
	}
	// This string parsing stuff was lifted from TPS
	var a, b int
	if a = strings.Index(logLine, "]:") + 3; a == -1 {
		return nil, nil
	}
	if b = strings.Index(logLine[a:], ":"); b == -1 {
		return nil, nil
	}
	clientIPString := logLine[a : a+b]
	clientIP := net.ParseIP(clientIPString)
	if clientIP == nil {
		return nil, nil
	}

	logLine = logLine[a+b:]
	// The first curly-braced block contains our request headers
	if a = strings.Index(logLine, "{"); a == -1 {
		return &clientIP, nil
	}
	if b = strings.Index(logLine[a:], "}"); b == -1 {
		return &clientIP, nil
	}
	bracketedHeaders := logLine[a : a+b]
	headers := strings.Split(bracketedHeaders, "|")
	if len(headers) < 7 {
		return &clientIP, nil
	}
	ipString := headers[7]
	cdnIP := net.ParseIP(ipString)
	if cdnIP == nil {
		return &clientIP, nil
	}
	return &clientIP, &cdnIP
}

func getLogTimestamp(logLine string) int64 {
	timestampStr := strings.Split(logLine, " ")[6]
	ts, _ := time.Parse("[02/Jan/2006:15:04:05.999]", timestampStr)

	return (ts.Unix())
}

type ipList struct {
	ips  []net.IP
	nets []net.IPNet
}

func readIPList(filename string) (*ipList, error) {
	var list ipList
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Index(strings.TrimSpace(line), "#") == 0 {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "/") {
			_, n, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("Unable to parse CIDR.\nLine:\n%s\nError:\n%s\n", line, err)
			}
			if n != nil {
				list.nets = append(list.nets, *n)
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				list.ips = append(list.ips, ip)
			} else {
				return nil, fmt.Errorf("Unable to parse IP address in list: %s\n", line)
			}
		}

	}
	return &list, nil
}

func (l *ipList) contains(checkIP *net.IP) bool {
	if l == nil {
		return false
	}
	for _, ip := range l.ips {
		if ip.Equal(*checkIP) {
			return true
		}
	}
	for _, net := range l.nets {
		if net.Contains(*checkIP) {
			return true
		}
	}

	return false
}

var hits = make(map[string]*ratelimit.Bucket)

func main() {
	app := cli.NewApp()
	app.Name = "fastly-ratelimit"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "whitelist, w",
			Usage: "Read `FILE` containing addresses which should whitelisted from any bans.",
		},
		cli.StringFlag{
			Name:  "listen, l",
			Usage: "Specify listen `ADDRESS:PORT`.",
			Value: "0.0.0.0:514",
		},
	}
	app.Action = func(c *cli.Context) error {
		channel := make(syslog.LogPartsChannel)
		handler := syslog.NewChannelHandler(channel)

		server := syslog.NewServer()
		server.SetFormat(syslog.RFC3164)
		server.SetHandler(handler)
		if err := server.ListenUDP(c.GlobalString("listen")); err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to listen: %s\n", err), -1)
		}
		if err := server.Boot(); err != nil {
			return cli.NewExitError(fmt.Sprintf("Unable to start server: %s\n", err), -1)
		}

		var whitelist *ipList
		var err error
		whitelistFile := c.GlobalString("whitelist")
		if whitelistFile != "" {
			if whitelist, err = readIPList(whitelistFile); err != nil {
				return cli.NewExitError(fmt.Sprintf("Error reading whitelist file: %s", err), -1)
			}
		}

		go func(channel syslog.LogPartsChannel) {
			for logParts := range channel {
				var line string
				var ok bool
				if line, ok = logParts["content"].(string); !ok || line == "" {
					continue
				}
				clientIP, cdnIP := getIPs(line)
				if cdnIP == nil || clientIP == nil {
					continue
				}
				if _, found := hits[cdnIP.String()]; !found {
					hits[cdnIP.String()] = ratelimit.NewBucket(time.Duration(3)*time.Minute, 180)
				}
				_, isSoonerThanMaxWait := hits[cdnIP.String()].TakeMaxDuration(1, 0)
				if !isSoonerThanMaxWait {
					if whitelist.contains(cdnIP) {
						//fmt.Println("but is whitelisted so we don't care.")
					} else {
						fmt.Printf("Over limit: %s\n", cdnIP.String())
					}
				}
			}
		}(channel)

		server.Wait()

		return nil
	}
	app.Run(os.Args)
}
