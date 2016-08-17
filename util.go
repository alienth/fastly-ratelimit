package main

import (
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/alienth/go-fastly"
)

// The edge ACL which we will be interacting with in fastly.
const aclName = "ratelimit"

func readConfig(filename string) (IPLists, error) {
	ipLists := make(IPLists)

	if _, err := toml.DecodeFile(filename, &ipLists); err != nil {
		return nil, fmt.Errorf("toml parsing error: %s", err)
	}

	for name, list := range ipLists {
		list.init(name)
	}

	return ipLists, nil
}

type ServiceDomains map[*fastly.Service][]fastly.Domain

func getServiceDomains() (ServiceDomains, error) {
	serviceDomains := make(ServiceDomains)

	services, err := client.ListServices(&fastly.ListServicesInput{})
	if err != nil {
		return nil, err
	}

	for _, s := range services {
		var i fastly.ListDomainsInput
		i.Service = s.ID
		i.Version = strconv.Itoa(int(s.ActiveVersion))
		domains, err := client.ListDomains(&i)
		if err != nil {
			return nil, err
		}

		var x fastly.ListACLsInput
		x.Service = s.ID
		x.Version = strconv.Itoa(int(s.ActiveVersion))
		acls, err := client.ListACLs(&x)
		if err != nil {
			return nil, err
		}
		var found bool
		for _, acl := range acls {
			if acl.Name == aclName {
				found = true
				break
			}
		}
		if found {
			for _, d := range domains {
				serviceDomains[s] = append(serviceDomains[s], *d)
			}
		}
	}
	return serviceDomains, nil
}

// getServiceByHost takes in a hostname and returns the faslty service
// associated with that hostname.
func (services ServiceDomains) getServiceByHost(hostname string) (*fastly.Service, error) {
	for s, domains := range services {
		for _, d := range domains {
			if d.Name == hostname {
				return s, nil
			}
		}
		for _, d := range domains {
			// The fastly hostname can contain wildcard records such as
			// *.stackoverflow.com. We use path.Match() to match on those.
			// A specific domain will override a wildcard, which is why
			// we're doing this in a second loop.
			found, err := path.Match(d.Name, strings.ToLower(hostname))
			if err != nil {
				// only possible error here would be a malformed pattern
				return nil, err
			}
			if found {
				return s, nil
			}
		}
	}

	return nil, nil
}

type duration struct {
	time.Duration
}

type ipNet struct {
	net.IPNet
}

func (d *duration) UnmarshalText(b []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(b))
	return err
}

// multiply takes in a factor and returns a new duration multiplied by that factor.
func (d duration) multiply(factor float64) duration {
	var newDuration duration
	newDuration.Duration = time.Duration(int(float64(d.Seconds())*factor)) * time.Second
	return newDuration
}

func (n *ipNet) UnmarshalText(b []byte) error {
	_, network, err := net.ParseCIDR(string(b))
	n.IPNet = *network
	return err
}
