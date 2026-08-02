// SPDX-License-Identifier: LGPL-3.0-only

package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

// MailClient groups the mail-admin API while sharing Client's HTTP base and
// transport. Client's MailX methods remain as compatibility wrappers.
type MailClient struct {
	client *Client
}

func (c *Client) Mail() *MailClient {
	return &MailClient{client: c}
}

func (m *MailClient) ListAccounts(ctx context.Context) ([]MailAccount, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.client.baseURL+"/api/mail/accounts", nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result []MailAccount
	return result, decodeResponse(resp, &result)
}

func (m *MailClient) CreateAccount(ctx context.Context, username, password string) (*MailAccount, error) {
	return m.createAccount(ctx, username, password)
}

func (m *MailClient) createAccount(ctx context.Context, username, password string) (*MailAccount, error) {
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.client.baseURL+"/api/mail/accounts", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.httpClient.Do(req)
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

func (m *MailClient) UpdateAccountPassword(ctx context.Context, username, password string) error {
	body, err := json.Marshal(map[string]string{"password": password})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, m.client.baseURL+"/api/mail/accounts/"+username, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}

func (m *MailClient) DeleteAccount(ctx context.Context, username string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, m.client.baseURL+"/api/mail/accounts/"+username, nil)
	if err != nil {
		return err
	}
	resp, err := m.client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}

func (m *MailClient) Authenticate(ctx context.Context, username, password string) (string, error) {
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.client.baseURL+"/api/mail/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Address string `json:"address"`
	}
	if err := decodeResponse(resp, &result); err != nil {
		return "", err
	}
	return result.Address, nil
}

func (m *MailClient) ListMessages(ctx context.Context, username, password string) ([]MailMessage, error) {
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.client.baseURL+"/api/mail/inbox", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result []MailMessage
	if err := decodeResponse(resp, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (m *MailClient) GetMessage(ctx context.Context, username, password string, messageID int64) (*MailMessageFull, error) {
	body, err := json.Marshal(map[string]any{"username": username, "password": password, "messageId": messageID})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.client.baseURL+"/api/mail/message", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.httpClient.Do(req)
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

func (m *MailClient) DeleteMessage(ctx context.Context, username, password string, messageID int64) error {
	body, err := json.Marshal(map[string]any{"username": username, "password": password, "messageId": messageID})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.client.baseURL+"/api/mail/delete", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}

func (m *MailClient) SetLocked(ctx context.Context, locked bool) error {
	body, err := json.Marshal(map[string]bool{"locked": locked})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.client.baseURL+"/api/mail/lock", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}
