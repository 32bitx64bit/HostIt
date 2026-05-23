package sdk

import "hostit/shared/apitypes"

type RegisterRequest = apitypes.RegisterRequest
type RegisterResponse = apitypes.RegisterResponse
type DomainsResponse = apitypes.DomainsResponse
type DomainSelectRequest = apitypes.DomainSelectRequest
type StatusResponse = apitypes.StatusResponse
type DomainOption = apitypes.DomainOption

type RouteUpdate = apitypes.RouteUpdate
type RouteStats = apitypes.RouteStats
type AppEvent = apitypes.AppEvent

type Route struct {
	Name       string `json:"name"`
	Proto      string `json:"proto"`
	PublicAddr string `json:"public_addr"`
	LocalAddr  string `json:"local_addr"`
	Domain     string `json:"domain,omitempty"`
}
