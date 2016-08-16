package main

import (
	"net"
	"strings"
	"time"
)

type logEntry struct {
	clientIP  *net.IP
	cdnIP     *net.IP
	timestamp time.Time
	host      Dimension
	backend   Dimension
	frontend  Dimension
}

// parseLog takes in an haproxy log line and returns a logEntry.
func parseLog(logLine string) *logEntry {
	var entry logEntry
	if logLine == "" {
		return nil
	}
	// This string parsing stuff was lifted from TPS
	var a, b int
	if a = strings.Index(logLine, "]:") + 3; a == -1 {
		return nil
	}
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
	entry.host = Dimension{Type: DimensionHost, Value: headers[2]}
	ipString := headers[7]
	cdnIP := net.ParseIP(ipString)
	if cdnIP == nil {
		return &entry
	}
	entry.cdnIP = &cdnIP
	return &entry
}
