package main

import (
	"fmt"
	"net"
	"path"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/alienth/go-fastly"
)

// The edge ACL which we will be interacting with in fastly.
const aclName = "ratelimit"

type appConfig struct {
	Main struct {
		LogFormat LogFormat
	} `toml:"main"`
	LogFormatOptions map[string]interface{}
	HookService      hookService
	Lists            IPLists

	logParser logParser
}

func readConfig(filename string) (appConfig, error) {
	config := appConfig{}

	if _, err := toml.DecodeFile(filename, &config); err != nil {
		return config, fmt.Errorf("toml parsing error: %s", err)
	}

	for name, list := range config.Lists {
		list.init(name)
	}

	config.logParser = config.Main.LogFormat.parser()
	if err := config.logParser.readOptions(config.LogFormatOptions); err != nil {
		return config, err
	}

	if len(config.Lists) < 1 {
		return config, fmt.Errorf("No IP lists defined in config file.")
	}

	if _, ok := config.Lists["_default_"]; !ok {
		return config, fmt.Errorf("No _default_ IP list defined in config file.")
	}

	return config, nil
}

type ServiceDomains map[*fastly.Service][]fastly.Domain

var aclByService = make(map[*fastly.Service]*fastly.ACL)

// This also happens to populate the aclByService variable which is used in
// several functions.
func getServiceDomains() (ServiceDomains, error) {
	serviceDomains := make(ServiceDomains)

	services, _, err := client.Service.List()
	if err != nil {
		return nil, err
	}

	for _, s := range services {
		domains, _, err := client.Domain.List(s.ID, s.Version)
		if err != nil {
			return nil, err
		}

		acls, _, err := client.ACL.List(s.ID, s.Version)
		if err != nil {
			return nil, err
		}
		var found bool
		for _, acl := range acls {
			if acl.Name == aclName {
				found = true
				aclByService[s] = acl
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
