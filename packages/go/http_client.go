package constellation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultTimeout = 30

// HTTPClient is a simple HTTP client for network operations
type HTTPClient struct {
	client  *http.Client
	baseURL string
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(baseURL string, timeout int) *HTTPClient {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &HTTPClient{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		baseURL: strings.TrimSuffix(baseURL, "/"),
	}
}

// Get makes a GET request
func (c *HTTPClient) Get(path string, result interface{}) error {
	url := c.baseURL + path

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return NewNetworkError(err.Error(), 0, "")
	}

	req.Header.Set("Accept", "application/json")

	return c.doRequest(req, result)
}

// Post makes a POST request
func (c *HTTPClient) Post(path string, body interface{}, result interface{}) error {
	url := c.baseURL + path

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return NewNetworkError(fmt.Sprintf("failed to marshal body: %v", err), 0, "")
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return NewNetworkError(err.Error(), 0, "")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return c.doRequest(req, result)
}

func (c *HTTPClient) doRequest(req *http.Request, result interface{}) error {
	resp, err := c.client.Do(req)
	if err != nil {
		if err, ok := err.(interface{ Timeout() bool }); ok && err.Timeout() {
			return ErrRequestTimeout
		}
		return NewNetworkError(err.Error(), 0, "")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewNetworkError(fmt.Sprintf("failed to read response: %v", err), resp.StatusCode, "")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NewNetworkError(
			fmt.Sprintf("HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
			resp.StatusCode,
			string(body),
		)
	}

	if result != nil && len(body) > 0 {
		if err := json.Unmarshal(body, result); err != nil {
			return NewNetworkError(fmt.Sprintf("failed to unmarshal response: %v", err), 0, string(body))
		}
	}

	return nil
}
