package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis"
	"net"
	"net/http"
	"time"
)

type ipMap struct {
	rwMutex
	m map[string]bool
}

type hookService struct {
	client       http.Client
	AddIPsUri    string
	RemoveIPsUri string
	SyncIPsUri   string
	hookedIPs    ipMap

	redis               *redis.Client
	RedisAddr           string
	RedisChannel        string
	RedisPublishAdds    bool
	RedisPublishRemoves bool
}

func (h *hookService) init() error {
	if h.RedisAddr != "" {
		if h.RedisChannel == "" {
			return fmt.Errorf("RedisChannel must be defined in config in order to publish hooks to redis.")
		}
		h.redis = redis.NewClient(&redis.Options{
			Addr: h.RedisAddr,
			DB:   0,
		})

		_, err := h.redis.Ping().Result()
		if err != nil {
			h.redis = nil
			return err
		}
	}
	return nil
}

func (h *hookService) sendHTTPHook(ips []net.IP, u string) error {
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(ips)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", u, buf)
	if err != nil {
		return err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}

	resp.Body.Close()

	return nil
}

func (h *hookService) Add(ipr ipRate) error {
	if h.AddIPsUri != "" {
		h.hookedIPs.Lock()
		defer h.hookedIPs.Unlock()
		// Short circuit already sent IPs
		if h.hookedIPs.m[ipr.ip.String()] == true {
			return nil
		}
		err := h.sendHTTPHook([]net.IP{*ipr.ip}, h.AddIPsUri)
		if err != nil {
			return err
		}

		h.hookedIPs.m[ipr.ip.String()] = true
	}

	if h.redis != nil && h.RedisPublishAdds {
		// This info isn't necessarily set by the time we get the hook,
		// so we're hacking it here.
		// TODO... don't do this.
		limitDuration := ipr.list.LimitDuration.multiply(float64(ipr.Strikes))
		expire := time.Now().Add(limitDuration.Duration)

		messageStruct := struct {
			IP     string    `json:"ip"`
			Expire time.Time `json:"expire"`
		}{ipr.ip.String(), expire}
		message, err := json.Marshal(messageStruct)
		if err != nil {
			return err
		}

		messageStr := string(message)
		cmd := h.redis.Publish(h.RedisChannel, messageStr)
		if err = cmd.Err(); err != nil {
			return err
		}
	}

	return nil
}

func (h *hookService) Remove(ipr ipRate) error {
	if h.RemoveIPsUri != "" {
		err := h.sendHTTPHook([]net.IP{*ipr.ip}, h.RemoveIPsUri)
		if err != nil {
			return err
		}

		h.hookedIPs.Lock()
		defer h.hookedIPs.Unlock()
		delete(h.hookedIPs.m, ipr.ip.String())
	}
	if h.RedisPublishRemoves {
		return fmt.Errorf("hookService does not yet implement publishing ratelimit removes to redis.")
	}

	return nil
}

func (h *hookService) Sync(ips []net.IP) error {
	if h.SyncIPsUri != "" {
		err := h.sendHTTPHook(ips, h.SyncIPsUri)
		if err != nil {
			return err
		}

		h.hookedIPs.Lock()
		defer h.hookedIPs.Unlock()
		h.hookedIPs.m = make(map[string]bool)
		for _, ip := range ips {
			h.hookedIPs.m[ip.String()] = true
		}
	}

	return nil
}
