package chapa

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInitializeAndVerify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/transaction/initialize":
			var req InitializeRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.TxRef != "tx-1" || req.Amount != "1500.00" || req.Currency != "ETB" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"message":"Hosted Link","status":"success","data":{"checkout_url":"https://checkout.example/tx-1"}}`))
		case "/transaction/verify/tx-1":
			_, _ = w.Write([]byte(`{"message":"Payment details","status":"success","data":{"status":"success","tx_ref":"tx-1","reference":"R1","amount":1500,"currency":"ETB"}}`))
		case "/transaction/verify/unknown":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Invalid transaction or Transaction not found","status":"failed","data":null}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "sk")
	req := InitializeRequest{Amount: "1500.00", Currency: "ETB", TxRef: "tx-1"}
	url, err := c.Initialize(context.Background(), req)
	if err != nil || url != "https://checkout.example/tx-1" {
		t.Fatalf("Initialize = %q, %v", url, err)
	}
	v, err := c.Verify(context.Background(), "tx-1")
	if err != nil || v.Status != "success" || v.Amount != 1500 || v.Currency != "ETB" || v.TxRef != "tx-1" {
		t.Fatalf("Verify = %+v, %v", v, err)
	}
	v, err = c.Verify(context.Background(), "unknown")
	if err != nil || v.Status != "pending" {
		t.Fatalf("Verify(unknown) = %+v, %v; want pending", v, err)
	}
	if _, err := New(srv.URL, "").Verify(context.Background(), "tx-1"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("unconfigured client: %v", err)
	}
}

func TestValidSignature(t *testing.T) {
	body := []byte(`{"tx_ref":"tx-1","status":"success"}`)
	h := hmac.New(sha256.New, []byte("whsec"))
	h.Write(body)
	sig := hex.EncodeToString(h.Sum(nil))
	if !ValidSignature("whsec", body, sig, "") {
		t.Fatal("valid payload signature rejected")
	}
	if ValidSignature("whsec", []byte(`{"tx_ref":"tx-2"}`), sig, "") {
		t.Fatal("signature of another payload accepted")
	}
	if ValidSignature("", body, sig, "") {
		t.Fatal("accepted without a secret")
	}
}
