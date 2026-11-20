package kms

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestRepo(baseURL string, maxRetries int) *Repository {
	return &Repository{
		baseURL:          baseURL,
		maxRetries:       maxRetries,
		backoffBaseDelay: time.Millisecond,
		conn:             &http.Client{Timeout: 5 * time.Second},
	}
}

func busyKMS(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, `{"keys":[]}`)
	}))
}

func okKMS() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"keys":[{"key_ID":"3ac4b1f2-0000-4000-8000-000000000001","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}`)
	}))
}

func TestKMSRequestNonOKDoesNotReadClosedBody(t *testing.T) {
	for _, status := range []int{
		http.StatusServiceUnavailable,
		http.StatusInternalServerError,
		http.StatusNotFound,
		http.StatusUnauthorized,
	} {
		for _, retries := range []int{0, 1, 2} {
			name := fmt.Sprintf("status=%d/retries=%d", status, retries)
			t.Run(name, func(t *testing.T) {
				srv := busyKMS(status)
				defer srv.Close()

				_, _, err := newTestRepo(srv.URL, retries).kmsRequest("/enc_keys")
				if err == nil {
					t.Fatal("expected an error when the KMS never returns 200")
				}
				if strings.Contains(err.Error(), "read on closed response body") {
					t.Errorf("body was read after being closed: %v", err)
				}
			})
		}
	}
}

func TestKMSRequestReportsAnExhaustedRetryLoop(t *testing.T) {
	srv := busyKMS(http.StatusServiceUnavailable)
	defer srv.Close()

	_, _, err := newTestRepo(srv.URL, 2).kmsRequest("/enc_keys")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "3 attempt(s)") {
		t.Errorf("the error should say how many attempts were made, got: %v", err)
	}
}

func TestKMSRequestSucceedsOnOK(t *testing.T) {
	srv := okKMS()
	defer srv.Close()

	id, key, err := newTestRepo(srv.URL, 2).kmsRequest("/enc_keys")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == "" {
		t.Error("no key_ID returned")
	}
	if len(key) == 0 {
		t.Error("no key material returned")
	}
}

func TestKMSRequestRetriesUntilTheKMSRecovers(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"keys":[]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"keys":[{"key_ID":"3ac4b1f2-0000-4000-8000-000000000002","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}`)
	}))
	defer srv.Close()

	id, _, err := newTestRepo(srv.URL, 3).kmsRequest("/enc_keys")
	if err != nil {
		t.Fatalf("expected recovery on the third attempt, got: %v", err)
	}
	if id == "" {
		t.Error("no key_ID returned after recovery")
	}
	if calls != 3 {
		t.Errorf("expected 3 requests, got %d", calls)
	}
}

func TestKMSRequestReportsATransportError(t *testing.T) {
	srv := okKMS()
	url := srv.URL
	srv.Close()

	_, _, err := newTestRepo(url, 0).kmsRequest("/enc_keys")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if errors.Is(err, ErrUnavailable) {
		t.Errorf("a transport error was reported as a status problem: %v", err)
	}
}

func TestKMSRequestKeepsTheObservedStatus(t *testing.T) {
	for _, code := range []int{
		http.StatusServiceUnavailable,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
	} {
		srv := busyKMS(code)
		_, _, err := newTestRepo(srv.URL, 1).kmsRequest("/enc_keys")
		srv.Close()

		if err == nil {
			t.Fatalf("%d: expected an error", code)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("%d", code)) {
			t.Errorf("%d: the status is not in the error, so 503 and 403 read "+
				"the same: %v", code, err)
		}
	}
}

func TestExhaustedRetriesAreIdentifiableWithoutStringMatching(t *testing.T) {
	srv := busyKMS(http.StatusServiceUnavailable)
	defer srv.Close()

	_, _, err := newTestRepo(srv.URL, 1).kmsRequest("/enc_keys")
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("errors.Is(err, ErrUnavailable) is false, so a caller can "+
			"only tell by reading the message: %v", err)
	}
}

func TestTheErrorLeaksNeitherBodyNorPath(t *testing.T) {
	const secretBody = "SENSITIVE-BODY-CONTENT"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(secretBody))
	}))
	defer srv.Close()

	_, _, err := newTestRepo(srv.URL, 0).kmsRequest("/dec_keys?key_ID=SECRET-KEY-ID")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secretBody) {
		t.Errorf("the response body reached the error: %v", err)
	}
	for _, leak := range []string{"dec_keys", "SECRET-KEY-ID", "key_ID"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the request path reached the error (%q): %v", leak, err)
		}
	}
}
