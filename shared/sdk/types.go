// SPDX-License-Identifier: LGPL-3.0-only

package sdk

import (
	"time"

	"hostit/shared/apitypes"
)

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

type MailAccount struct {
	Username string `json:"username"`
	Address  string `json:"address"`
}

type MailMessage struct {
	ID      int64     `json:"id"`
	Mailbox string    `json:"mailbox"`
	Date    time.Time `json:"date"`
	From    string    `json:"from"`
	To      string    `json:"to"`
	Subject string    `json:"subject"`
	Flags   []string  `json:"flags,omitempty"`
	Size    int       `json:"size"`
}

type MailMessageFull struct {
	MailMessage
	Body string `json:"body"`
}
