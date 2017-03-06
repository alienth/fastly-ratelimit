package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type logParser interface {
	parse(logLine string) *logEntry
	readOptions(map[string]interface{}) error
}

type LogFormat int

const (
	HaproxyHTTPLogFormat LogFormat = iota
)

func (f *LogFormat) UnmarshalText(b []byte) error {
	switch string(b) {
	case "HaproxyHTTP":
		*f = HaproxyHTTPLogFormat
	default:
		return fmt.Errorf("Unrecognized log format type %s\n", string(b))
	}
	return nil
}

func (f *LogFormat) parser() logParser {
	switch *f {
	case HaproxyHTTPLogFormat:
		return &HaproxyHTTPLogParser{}
	}
	return nil
}

type HaproxyHTTPLogParser struct {
	Options struct {
		UserAgentRequestHeader uint
		HostRequestHeader      uint
		TrueClientIPHeader     uint
	}
}

type logEntry struct {
	clientIP  *net.IP
	cdnIP     *net.IP
	timestamp time.Time
	host      Dimension
	backend   Dimension
	frontend  Dimension
	useragent Dimension
}

func (p *HaproxyHTTPLogParser) readOptions(options map[string]interface{}) error {

	converter := func(s string) (uint, error) {
		i, err := strconv.Atoi(s)
		if err != nil {
			return 0, err
		}
		return uint(i) - 1, nil
	}

	var err error
	for k, v := range options {
		switch k {
		case "UserAgentRequestHeader":
			switch v := v.(type) {
			case string:
				if p.Options.UserAgentRequestHeader, err = converter(v); err != nil {
					return fmt.Errorf("Invalid value for option %s: %s", k, v)
				}
			case int64:
				p.Options.UserAgentRequestHeader = uint(v)
			}
		case "HostRequestHeader":
			switch v := v.(type) {
			case string:
				if p.Options.HostRequestHeader, err = converter(v); err != nil {
					return fmt.Errorf("Invalid value for option %s: %s", k, v)
				}
			case int64:
				p.Options.HostRequestHeader = uint(v)
			}
		case "TrueClientIPRequestHeader":
			switch v := v.(type) {
			case string:
				if p.Options.TrueClientIPHeader, err = converter(v); err != nil {
					return fmt.Errorf("Invalid value for option %s: %s", k, v)
				}
			case int64:
				p.Options.TrueClientIPHeader = uint(v)
			}
		default:
			return fmt.Errorf("Unrecognized option %s", k)
		}
	}

	fmt.Println(options)
	fmt.Println(p.Options)

	// TODO Fix this. We can have headers in position 0 :/
	if p.Options.TrueClientIPHeader == 0 || p.Options.HostRequestHeader == 0 {
		return fmt.Errorf("Must specify HostRequestHeader and TrueClientIPRequestHeader at minimum.")
	}

	return nil
}

// parseLog takes in an haproxy log line and returns a logEntry.
func (p *HaproxyHTTPLogParser) parse(logLine string) *logEntry {
	var entry logEntry
	if logLine == "" {
		return nil
	}
	// This string parsing stuff was lifted from TPS
	var a, b int
	a = 0
	if b = strings.Index(logLine[a:], ":"); b == -1 {
		return nil
	}
	clientIPString := logLine[a : a+b]
	clientIP := net.ParseIP(clientIPString)
	if clientIP == nil {
		return nil
	}
	entry.clientIP = &clientIP

	logLine = logLine[a+b:]
	// The subsequent square-bracketed string contains our timestamp
	if a = strings.Index(logLine, "[") + 1; a == -1 {
		return &entry
	}
	if b = strings.Index(logLine[a:], "]"); b == -1 {
		return &entry
	}
	timestampStr := logLine[a : a+b]
	entry.timestamp, _ = time.Parse("02/Jan/2006:15:04:05.999", timestampStr)

	logLine = logLine[a+b:]
	// The subsequent string is our frontend
	if a = strings.Index(logLine, " ") + 1; a == -1 {
		return &entry
	}
	if b = strings.Index(logLine[a:], " "); b == -1 {
		return &entry
	}
	entry.frontend = Dimension{Type: DimensionFrontend, Value: logLine[a : a+b]}

	logLine = logLine[a+b:]
	// The subsequent string is our backend
	if a = strings.Index(logLine, " ") + 1; a == -1 {
		return &entry
	}
	if b = strings.Index(logLine[a:], "/"); b == -1 {
		return &entry
	}
	entry.backend = Dimension{Type: DimensionBackend, Value: logLine[a : a+b]}

	logLine = logLine[a+b:]
	// The first curly-braced block contains our request headers
	if a = strings.Index(logLine, "{"); a == -1 {
		return &entry
	}
	if b = strings.Index(logLine[a:], "}"); b == -1 {
		return &entry
	}
	bracketedHeaders := logLine[a : a+b]
	headers := strings.Split(bracketedHeaders, "|")
	if len(headers) < 7 {
		return &entry
	}
	entry.useragent = Dimension{Type: DimensionUseragent, Value: headers[p.Options.UserAgentRequestHeader]}
	entry.host = Dimension{Type: DimensionHost, Value: headers[p.Options.HostRequestHeader]}
	ipString := headers[p.Options.TrueClientIPHeader]
	cdnIP := net.ParseIP(ipString)
	if cdnIP == nil {
		return &entry
	}
	entry.cdnIP = &cdnIP
	return &entry
}
