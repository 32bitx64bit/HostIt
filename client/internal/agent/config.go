package agent

type RouteConfig struct {
	Name         string
	Proto        string // "tcp", "udp", or "both"
	LocalTCPAddr string // local TCP target (host:port)
	LocalUDPAddr string // local UDP target (host:port)
}

type Config struct {
	ControlAddr string
	DataAddr    string
	Token       string
	// LocalAddr is kept for backwards compatibility. If Routes is empty, a default
	// TCP route named "default" is created from LocalAddr.
	LocalAddr string
	Routes    []RouteConfig
}
