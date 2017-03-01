package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"sync"
)

type ipMap struct {
	sync.RWMutex
	m map[string]bool
}

type hookService struct {
	client       http.Client
	AddIPsUri    string
	RemoveIPsUri string
	SyncIPsUri   string
	hookedIPs    ipMap
}

func (h *hookService) send(ips []net.IP, u string) error {
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

func (h *hookService) Add(ip net.IP) error {
	h.hookedIPs.Lock()
	defer h.hookedIPs.Unlock()
	// Short circuit already sent IPs
	if h.hookedIPs.m[ip.String()] == true {
		return nil
	}
	err := h.send([]net.IP{ip}, h.AddIPsUri)
	if err != nil {
		return err
	}

	h.hookedIPs.m[ip.String()] = true

	return nil
}

func (h *hookService) Remove(ip net.IP) error {
	err := h.send([]net.IP{ip}, h.RemoveIPsUri)
	if err != nil {
		return err
	}

	h.hookedIPs.Lock()
	defer h.hookedIPs.Unlock()
	delete(h.hookedIPs.m, ip.String())

	return nil
}

func (h *hookService) Sync(ips []net.IP) error {
	err := h.send(ips, h.SyncIPsUri)
	if err != nil {
		return err
	}

	h.hookedIPs.Lock()
	defer h.hookedIPs.Unlock()
	h.hookedIPs.m = make(map[string]bool)
	for _, ip := range ips {
		h.hookedIPs.m[ip.String()] = true
	}

	return nil
}
