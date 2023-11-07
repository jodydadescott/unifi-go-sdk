package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"
)

const (
	Version = "1.0"
)

type Client struct {
	username    string
	password    string
	hostname    string
	httpClient  *http.Client
	cookieCache *http.Cookie
}

func New(config *Config) *Client {

	zap.L().Debug(fmt.Sprintf("Version %s", Version))

	if config.Username == "" {
		panic("username is required")
	}

	if config.Password == "" {
		panic("password is required")
	}

	if config.Hostname == "" {
		panic("hostname is required")
	}

	return &Client{
		username: config.Username,
		password: config.Password,
		hostname: config.Hostname,
		httpClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}},
	}
}

func (t *Client) GetAuthCookie() (*http.Cookie, error) {

	authRequest := &AuthRequest{
		Username: t.username,
		Password: t.password,
	}

	authRequestRaw, _ := json.Marshal(authRequest)

	req, err := http.NewRequest("POST", t.hostname+"/api/auth/login", bytes.NewBuffer(authRequestRaw))
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		return nil, err
	}

	resp, err := t.httpClient.Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "TOKEN" {
				return cookie, nil
			}
		}
		return nil, fmt.Errorf("no cookie found in response")
	}

	defer resp.Body.Close()
	message, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf(string(message))
}

func (t *Client) GetClients() ([]UnifiClient, error) {

	bytes, err := t.httpRequest("GET", "/proxy/network/v2/api/site/default/clients/active?includeTrafficUsage=true&includeUnifiDevices=true")

	if err != nil {
		return nil, err
	}

	keys := make([]UnifiClient, 0)
	err = json.Unmarshal(bytes, &keys)

	if err != nil {
		return nil, err
	}

	var result []UnifiClient

	for _, v := range keys {
		result = append(result, v)
	}

	return result, nil
}

func (t *Client) GetDevices() (*UnifiDevices, error) {

	bytes, err := t.httpRequest("GET", "/proxy/network/v2/api/site/default/device?separateUnmanaged=true&includeTrafficUsage=true")

	if err != nil {
		return nil, err
	}

	var unifiDevices UnifiDevices
	err = json.Unmarshal(bytes, &unifiDevices)

	if err != nil {
		return nil, err
	}

	return &unifiDevices, nil
}

func (t *Client) GetEnrichedConfiguration() ([]EnrichedConfiguration, error) {

	bytes, err := t.httpRequest("GET", "/proxy/network/v2/api/site/default/lan/enriched-configuration")

	if err != nil {
		return nil, err
	}

	keys := make([]EnrichedConfiguration, 0)
	err = json.Unmarshal(bytes, &keys)

	if err != nil {
		return nil, err
	}

	var result []EnrichedConfiguration

	for _, v := range keys {
		result = append(result, v)
	}

	return result, nil
}

func (t *Client) httpRequest(op, uri string) ([]byte, error) {

	makeRequest := func() (*http.Response, error) {

		if t.cookieCache == nil {
			zap.L().Debug("cookie does not exist; fetching")
			cookie, err := t.GetAuthCookie()
			if err != nil {
				return nil, err
			}
			t.cookieCache = cookie
		} else {
			zap.L().Debug("cookie does exist")
		}

		req, err := http.NewRequest(op, t.hostname+uri, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(t.cookieCache)

		resp, err := t.httpClient.Do(req)

		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	converToBytes := func(resp *http.Response) ([]byte, error) {
		defer resp.Body.Close()
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return bytes, nil
	}

	var resp *http.Response
	var err error

	resp, err = makeRequest()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		zap.L().Debug("cookie is unauthorized; trying again")
		t.cookieCache = nil
		resp, err = makeRequest()
		if err != nil {
			return nil, err
		}
	}

	if resp.StatusCode == http.StatusOK {
		return converToBytes(resp)
	}

	errorBytes, err := converToBytes(resp)
	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf(string(errorBytes))
}
