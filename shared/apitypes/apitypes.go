package apitypes

type RouteRequest struct {
	RequestID  string `json:"request_id"`
	Name       string `json:"name"`
	Proto      string `json:"proto"`
	LocalAddr  string `json:"local_addr"`
	PublicPort int    `json:"public_port"`
	Domain     string `json:"domain"`
	Encrypted  bool   `json:"encrypted"`
	Source     string `json:"source"`
}

type RouteResponse struct {
	RequestID        string         `json:"request_id"`
	Status           string         `json:"status"`
	Name             string         `json:"name"`
	Proto            string         `json:"proto,omitempty"`
	PublicAddr       string         `json:"public_addr,omitempty"`
	LocalAddr        string         `json:"local_addr,omitempty"`
	Domain           string         `json:"domain,omitempty"`
	AvailableDomains []DomainOption `json:"available_domains,omitempty"`
	Error            string         `json:"error,omitempty"`
}

type DomainOption struct {
	Host      string `json:"host"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	UsedBy    string `json:"used_by,omitempty"`
}

type RouteConfirm struct {
	RequestID string `json:"request_id"`
	Name      string `json:"name"`
	Domain    string `json:"domain"`
}

type RouteAck struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	Name       string `json:"name"`
	Domain     string `json:"domain,omitempty"`
	PublicAddr string `json:"public_addr,omitempty"`
	Error      string `json:"error,omitempty"`
}

type RouteRemove struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type RouteRemoveAck struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type RegisterRequest struct {
	Name       string `json:"name"`
	Proto      string `json:"proto"`
	LocalPort  int    `json:"local_port"`
	LocalHost  string `json:"local_host,omitempty"`
	PublicPort int    `json:"public_port,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Encrypted  bool   `json:"encrypted,omitempty"`
}

type RegisterResponse struct {
	Status           string         `json:"status"`
	RequestID        string         `json:"request_id,omitempty"`
	RouteName        string         `json:"route_name"`
	PublicAddr       string         `json:"public_addr,omitempty"`
	LocalAddr        string         `json:"local_addr,omitempty"`
	Proto            string         `json:"proto,omitempty"`
	Domain           string         `json:"domain,omitempty"`
	AvailableDomains []DomainOption `json:"available_domains,omitempty"`
}

type DomainsResponse struct {
	Base      string         `json:"base"`
	Available []DomainOption `json:"available"`
}

type DomainSelectRequest struct {
	RequestID string `json:"request_id"`
	RouteName string `json:"route_name"`
	Domain    string `json:"domain"`
}

type StatusResponse struct {
	Connected   bool   `json:"connected"`
	Server      string `json:"server"`
	Version     string `json:"version"`
	RoutesCount int    `json:"routes_count"`
	DomainBase  string `json:"domain_base,omitempty"`
}

type APIKey struct {
	Key              string   `json:"key"`
	Label            string   `json:"label"`
	Permissions      []string `json:"permissions"`
	OwnedRoutePrefix string  `json:"owned_route_prefix,omitempty"`
}

type RouteUpdate struct {
	RequestID  string `json:"request_id"`
	Name       string `json:"name"`
	LocalAddr  string `json:"local_addr,omitempty"`
	PublicPort int    `json:"public_port,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Encrypted  *bool  `json:"encrypted,omitempty"`
}

type RouteUpdateAck struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Name      string `json:"name"`
	Error     string `json:"error,omitempty"`
}

type RouteStats struct {
	Name       string `json:"name"`
	Proto      string `json:"proto"`
	PublicAddr string `json:"public_addr"`
	LocalAddr  string `json:"local_addr"`
	Domain     string `json:"domain,omitempty"`
	Connected  bool   `json:"connected"`
	Source     string `json:"source"`
}

type AppEvent struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
	RouteName string `json:"route_name,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

type AppsConfig struct {
	Apps []AppConfig `json:"apps"`
}

type AppConfig struct {
	Name       string `json:"name"`
	Proto      string `json:"proto"`
	LocalPort  int    `json:"local_port"`
	LocalHost  string `json:"local_host,omitempty"`
	PublicPort int    `json:"public_port,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Encrypted  bool   `json:"encrypted,omitempty"`
	AutoStart  bool   `json:"auto_start,omitempty"`
}
