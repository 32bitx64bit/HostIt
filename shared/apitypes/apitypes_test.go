// SPDX-License-Identifier: LGPL-3.0-only

package apitypes

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRouteRequestRoundTrip(t *testing.T) {
	orig := RouteRequest{
		RequestID:  "abc123",
		Name:       "my-route",
		Proto:      "tcp",
		LocalAddr:  "127.0.0.1:8080",
		PublicPort: 9090,
		Domain:     "my.example.com",
		Encrypted:  true,
		Source:     "api",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RouteRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != orig {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestRouteResponseRoundTrip(t *testing.T) {
	orig := RouteResponse{
		RequestID:  "req-1",
		Status:     "active",
		Name:       "app",
		Proto:      "tcp",
		PublicAddr: ":9090",
		LocalAddr:  "127.0.0.1:3000",
		Domain:     "app.example.com",
		AvailableDomains: []DomainOption{
			{Host: "app.example.com", Available: true},
			{Host: "app2.example.com", Available: false, Reason: "already in use", UsedBy: "other"},
		},
		Error: "",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RouteResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, orig) {
		t.Fatalf("round-trip mismatch:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

func TestRouteResponseOmitempty(t *testing.T) {
	orig := RouteResponse{
		RequestID: "req-2",
		Status:    "failed",
		Name:      "bad",
		Error:     "invalid proto",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["proto"]; ok {
		t.Error("proto should be omitted when empty")
	}
	if _, ok := m["public_addr"]; ok {
		t.Error("public_addr should be omitted when empty")
	}
	if _, ok := m["available_domains"]; ok {
		t.Error("available_domains should be omitted when nil")
	}
}

func TestDomainOptionRoundTrip(t *testing.T) {
	cases := []DomainOption{
		{Host: "a.example.com", Available: true},
		{Host: "b.example.com", Available: false, Reason: "taken", UsedBy: "app1"},
	}
	for _, orig := range cases {
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}
		var decoded DomainOption
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded != orig {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
		}
	}
}

func TestRouteConfirmRoundTrip(t *testing.T) {
	orig := RouteConfirm{
		RequestID: "req-3",
		Name:      "myapp",
		Domain:    "myapp.example.com",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RouteConfirm
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != orig {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestRouteAckRoundTrip(t *testing.T) {
	cases := []RouteAck{
		{RequestID: "r1", Status: "active", Name: "app", Domain: "app.example.com", PublicAddr: ":9090"},
		{RequestID: "r2", Status: "failed", Name: "bad", Error: "conflict"},
	}
	for _, orig := range cases {
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}
		var decoded RouteAck
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded != orig {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
		}
	}
}

func TestRouteRemoveRoundTrip(t *testing.T) {
	orig := RouteRemove{Name: "myapp", Source: "api"}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RouteRemove
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != orig {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestRouteRemoveAckRoundTrip(t *testing.T) {
	cases := []RouteRemoveAck{
		{Name: "app", OK: true},
		{Name: "app", OK: false, Error: "not found"},
	}
	for _, orig := range cases {
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}
		var decoded RouteRemoveAck
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded != orig {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
		}
	}
}

func TestRegisterRequestRoundTrip(t *testing.T) {
	orig := RegisterRequest{
		Name:       "web",
		Proto:      "tcp",
		LocalPort:  8080,
		LocalHost:  "192.168.1.1",
		PublicPort: 9090,
		Domain:     "web.example.com",
		Encrypted:  true,
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RegisterRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != orig {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestRegisterRequestDefaults(t *testing.T) {
	orig := RegisterRequest{
		Name:      "minimal",
		Proto:     "tcp",
		LocalPort: 8080,
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["local_host"]; ok {
		t.Error("local_host should be omitted when empty")
	}
	if _, ok := m["public_port"]; ok {
		t.Error("public_port should be omitted when zero")
	}
	if _, ok := m["domain"]; ok {
		t.Error("domain should be omitted when empty")
	}
	if _, ok := m["encrypted"]; ok {
		t.Error("encrypted should be omitted when false")
	}
}

func TestRegisterResponseRoundTrip(t *testing.T) {
	orig := RegisterResponse{
		Status:     "active",
		RequestID:  "req-10",
		RouteName:  "app",
		PublicAddr: ":9090",
		LocalAddr:  "127.0.0.1:3000",
		Proto:      "tcp",
		Domain:     "app.example.com",
		AvailableDomains: []DomainOption{
			{Host: "app.example.com", Available: true},
		},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RegisterResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, orig) {
		t.Fatalf("round-trip mismatch:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

func TestDomainsResponseRoundTrip(t *testing.T) {
	orig := DomainsResponse{
		Base: "example.com",
		Available: []DomainOption{
			{Host: "app.example.com", Available: true},
			{Host: "api.example.com", Available: false, UsedBy: "other-route"},
		},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DomainsResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, orig) {
		t.Fatalf("round-trip mismatch:\ngot  %+v\nwant %+v", decoded, orig)
	}
}

func TestDomainSelectRequestRoundTrip(t *testing.T) {
	orig := DomainSelectRequest{
		RequestID: "req-5",
		RouteName: "myapp",
		Domain:    "myapp.example.com",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DomainSelectRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != orig {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestStatusResponseRoundTrip(t *testing.T) {
	orig := StatusResponse{
		Connected:   true,
		Server:      "tunnel.example.com",
		Version:     "1.0.0",
		RoutesCount: 5,
		DomainBase:  "example.com",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded StatusResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != orig {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestAPIKeyRoundTrip(t *testing.T) {
	orig := APIKey{
		Key:              "hit_abc123",
		Label:            "myapp",
		Permissions:      []string{"routes:register", "routes:list"},
		OwnedRoutePrefix: "myapp",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded APIKey
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, orig) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestAPIKeyEmptyPrefix(t *testing.T) {
	orig := APIKey{
		Key:         "hit_xyz",
		Label:       "test",
		Permissions: []string{"*"},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["owned_route_prefix"]; ok {
		t.Error("owned_route_prefix should be omitted when empty")
	}
}
