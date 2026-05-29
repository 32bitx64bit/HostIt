package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type envelope struct {
	Status  string          `json:"status"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func decodeResponse(resp *http.Response, out any) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var e envelope
		if err := json.Unmarshal(body, &e); err != nil || e.Message == "" {
			return fmt.Errorf("request failed: %d", resp.StatusCode)
		}
		return fmt.Errorf("%s", e.Message)
	}
	if len(body) == 0 {
		return nil
	}
	var e envelope
	if err := json.Unmarshal(body, &e); err != nil {
		return err
	}
	if e.Status != "ok" {
		return fmt.Errorf("unexpected status: %s", e.Status)
	}
	if out != nil && len(e.Data) > 0 {
		return json.Unmarshal(e.Data, out)
	}
	return nil
}

func (c *Client) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result RegisterResponse
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) ListRoutes(ctx context.Context) ([]Route, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/routes", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var routes []Route
	if err := decodeResponse(resp, &routes); err != nil {
		return nil, err
	}
	return routes, nil
}

func (c *Client) RemoveRoute(ctx context.Context, name string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/routes/"+name, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}

func (c *Client) ListDomains(ctx context.Context) (*DomainsResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/domains", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result DomainsResponse
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) SelectDomain(ctx context.Context, requestID, routeName, domain string) (*RegisterResponse, error) {
	body, err := json.Marshal(DomainSelectRequest{RequestID: requestID, RouteName: routeName, Domain: domain})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/domains/select", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result RegisterResponse
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result StatusResponse
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) UpdateRoute(ctx context.Context, name string, req RouteUpdate) (*RegisterResponse, error) {
	bodyMap := map[string]any{"name": name}
	if req.LocalAddr != "" {
		host, portStr, err := net.SplitHostPort(req.LocalAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid LocalAddr %q: %w", req.LocalAddr, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port in LocalAddr %q: %w", req.LocalAddr, err)
		}
		if port > 0 {
			bodyMap["local_port"] = port
			if host != "" && host != "127.0.0.1" {
				bodyMap["local_host"] = host
			}
		}
	}
	if req.PublicPort > 0 {
		bodyMap["public_port"] = req.PublicPort
	}
	if req.Domain != "" {
		bodyMap["domain"] = req.Domain
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/routes/update", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result RegisterResponse
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) RouteStats(ctx context.Context, name string) (*RouteStats, error) {
	u := c.baseURL + "/api/v1/route/stats?name=" + url.QueryEscape(name)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result RouteStats
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) ListMailAccounts(ctx context.Context) ([]MailAccount, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/mail/accounts", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var accts []MailAccount
	if err := decodeResponse(resp, &accts); err != nil {
		return nil, err
	}
	return accts, nil
}

func (c *Client) CreateMailAccount(ctx context.Context, username, password string) (*MailAccount, error) {
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/mail/accounts", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result MailAccount
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) UpdateMailAccountPassword(ctx context.Context, username, password string) error {
	body, err := json.Marshal(map[string]string{"password": password})
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+"/api/mail/accounts/"+username, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}

func (c *Client) DeleteMailAccount(ctx context.Context, username string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/mail/accounts/"+username, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}

func (c *Client) AuthenticateMail(ctx context.Context, username, password string) (string, error) {
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/mail/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Username string `json:"username"`
		Address  string `json:"address"`
	}
	if err := decodeResponse(resp, &result); err != nil {
		return "", err
	}
	return result.Address, nil
}

func (c *Client) ListMailMessages(ctx context.Context, username, password string) ([]MailMessage, error) {
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/mail/inbox", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var msgs []MailMessage
	if err := decodeResponse(resp, &msgs); err != nil {
		return nil, err
	}
	return msgs, nil
}

func (c *Client) GetMailMessage(ctx context.Context, username, password string, messageID int64) (*MailMessageFull, error) {
	body, err := json.Marshal(map[string]any{"username": username, "password": password, "messageId": messageID})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/mail/message", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result MailMessageFull
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) DeleteMailMessage(ctx context.Context, username, password string, messageID int64) error {
	body, err := json.Marshal(map[string]any{"username": username, "password": password, "messageId": messageID})
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/mail/delete", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}

func (c *Client) LockMailService(ctx context.Context, locked bool) error {
	body, err := json.Marshal(map[string]bool{"locked": locked})
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/mail/lock", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}

func (c *Client) EventsURL() string {
	return strings.Replace(c.baseURL, "http", "ws", 1) + "/api/v1/events"
}
