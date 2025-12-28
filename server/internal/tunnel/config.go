package tunnel

import "time"

type RouteConfig struct {
	Name       string
	Proto      string // "tcp", "udp", or "both"
	PublicAddr string // listen address (host:port)
}

type ServerConfig struct {
	ControlAddr string
	DataAddr    string
	// PublicAddr is kept for backwards compatibility. If Routes is empty, a default
	// TCP route named "default" is created from PublicAddr.
	PublicAddr string
	Token       string
	PairTimeout time.Duration
	Routes      []RouteConfig
}
