// Package chapa is a minimal client for the Chapa payment API (https://developer.chapa.co):
// initialize a hosted checkout, verify a transaction, and check webhook signatures.
package chapa

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is Chapa's API endpoint.
const DefaultBaseURL = "https://api.chapa.co/v1"

// ErrNotConfigured is returned when no secret key is set.
var ErrNotConfigured = errors.New("chapa: CHAPA_SECRET_KEY is not set")

// Client calls the Chapa API with a secret key.
type Client struct {
	baseURL    string
	secretKey  string
	httpClient *http.Client
}

// New returns a client. An empty secretKey gives a client whose calls return ErrNotConfigured.
func New(baseURL, secretKey string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		secretKey:  secretKey,
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

// Configured reports whether a secret key is set.
func (c *Client) Configured() bool {
	return c != nil && c.secretKey != ""
}

// InitializeRequest describes a hosted checkout.
type InitializeRequest struct {
	Amount      string `json:"amount"`
	Currency    string `json:"currency"`
	Email       string `json:"email,omitempty"`
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	TxRef       string `json:"tx_ref"`
	CallbackURL string `json:"callback_url,omitempty"`
	ReturnURL   string `json:"return_url,omitempty"`
	// Chapa limits the title to 16 characters and both fields to letters, digits, spaces,
	// hyphens, underscores and dots.
	Customization struct {
		Title       string `json:"title,omitempty"`
		Description string `json:"description,omitempty"`
	} `json:"customization"`
}

// Initialize creates a hosted checkout and returns the URL to send the customer to.
func (c *Client) Initialize(ctx context.Context, req InitializeRequest) (string, error) {
	var resp struct {
		Message interface{} `json:"message"`
		Status  string      `json:"status"`
		Data    struct {
			CheckoutURL string `json:"checkout_url"`
		} `json:"data"`
		CheckoutURL string `json:"checkout_url"`
	}
	if err := c.do(ctx, http.MethodPost, "/transaction/initialize", req, &resp); err != nil {
		return "", err
	}
	checkout := firstNonEmpty(resp.Data.CheckoutURL, resp.CheckoutURL)
	if resp.Status != "success" || checkout == "" {
		return "", fmt.Errorf("chapa: initialize failed: %v", resp.Message)
	}
	return checkout, nil
}

// Verification is the outcome of a transaction, as reported by Chapa.
type Verification struct {
	Status    string // success | pending | failed
	TxRef     string
	Reference string
	Amount    float64
	Currency  string
}

// Verify asks Chapa for a transaction's status. It is the source of truth: callbacks, webhooks
// and the customer's return to the site only trigger a verification.
func (c *Client) Verify(ctx context.Context, txRef string) (*Verification, error) {
	var resp struct {
		Message interface{} `json:"message"`
		Status  string      `json:"status"`
		Data    *struct {
			Status    string      `json:"status"`
			TxRef     string      `json:"tx_ref"`
			Reference string      `json:"reference"`
			Amount    json.Number `json:"amount"`
			Currency  string      `json:"currency"`
		} `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, "/transaction/verify/"+url.PathEscape(txRef), nil, &resp)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		// Chapa does not know the transaction yet (the customer has not paid).
		return &Verification{Status: "pending", TxRef: txRef}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return &Verification{Status: "pending", TxRef: txRef}, nil
	}
	amount, _ := strconv.ParseFloat(resp.Data.Amount.String(), 64)
	return &Verification{
		Status: strings.ToLower(resp.Data.Status), TxRef: resp.Data.TxRef, Reference: resp.Data.Reference,
		Amount: amount, Currency: strings.ToUpper(resp.Data.Currency),
	}, nil
}

// ValidSignature checks a webhook's x-chapa-signature (HMAC-SHA256 of the raw body) or
// chapa-signature (HMAC-SHA256 of the secret itself) header against the webhook secret.
func ValidSignature(secret string, body []byte, payloadSignature, secretSignature string) bool {
	if secret == "" {
		return false
	}
	mac := func(data []byte) string {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}
	if payloadSignature != "" && hmac.Equal([]byte(strings.ToLower(payloadSignature)), []byte(mac(body))) {
		return true
	}
	return secretSignature != "" && hmac.Equal([]byte(strings.ToLower(secretSignature)), []byte(mac([]byte(secret))))
}

// APIError is a non-2xx response from Chapa.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("chapa: HTTP %d: %s", e.StatusCode, e.Message)
}

func (c *Client) do(ctx context.Context, method, path string, body, out interface{}) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("chapa: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("chapa: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message interface{} `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		msg := fmt.Sprint(e.Message)
		if e.Message == nil {
			msg = strings.TrimSpace(string(data))
		}
		return &APIError{StatusCode: resp.StatusCode, Message: msg}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("chapa: decode response: %w", err)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
