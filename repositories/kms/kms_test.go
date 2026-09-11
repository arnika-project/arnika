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

// newTestRepo builds a Repository against a test server without going through
// NewRepository, which calls log.Fatal on certificate problems.
func newTestRepo(baseURL string, maxRetries int) *Repository {
	return &Repository{
		baseURL:          baseURL,
		maxRetries:       maxRetries,
		backoffBaseDelay: time.Millisecond,
		conn:             &http.Client{Timeout: 5 * time.Second},
		Managed:          true,
	}
}

// A KMS that is reachable but cannot serve a key right now. ETSI GS QKD 014
// leaves the status open, and an implementation that answers 503 when its key
// pool is momentarily empty is behaving reasonably.
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

// TestKMSRequestNonOKDoesNotReadClosedBody is the regression test.
//
// kmsRequest closed the response body inside the retry loop and read it after
// the loop. A non-2xx is a successful HTTP transaction, so err was nil, the
// nil-check did not return, and io.ReadAll ran against an already-closed body:
//
//	http: read on closed response body
//
// The caller sees that instead of "the KMS had no key", which in a QKD
// deployment means the two ends silently end up on different key material.
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

// The error must also say what went wrong. An exhausted retry loop used to be
// indistinguishable from a parse failure, because the status was never turned
// into an error of its own.
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

// Not vacuous: the happy path must still work, or the two tests above would
// pass on a function that always fails.
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

// A KMS that fails and then recovers must be retried, not abandoned -- the fix
// clears res between attempts, so this checks the clearing did not break the
// retry it exists to make safe.
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

// A transport-level failure (nothing listening) must still surface as itself.
func TestKMSRequestReportsATransportError(t *testing.T) {
	srv := okKMS()
	url := srv.URL
	srv.Close() // nothing is listening now

	_, _, err := newTestRepo(url, 0).kmsRequest("/enc_keys")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	// errors.Is, not a substring. The point of the assertion is that a
	// transport failure is NOT the exhausted-retry case, and asking that
	// question of the sentinel says so directly -- where matching on wording
	// only holds until someone rephrases the message.
	if errors.Is(err, ErrUnavailable) {
		t.Errorf("a transport error was reported as a status problem: %v", err)
	}
}

// TestKMSRequestKeepsTheObservedStatus is the follow-up requested in review on
// PR #44: an exhausted retry loop must say WHICH status it kept seeing.
//
// 503 means the key pool is momentarily empty and the next interval will
// recover. 401, 403 and 404 mean the tunnel is coasting on a stale PSK with no
// fresh QKD material coming, and no amount of waiting fixes it. Reporting them
// identically leaves an operator nothing to alert on -- which SECURITY.md asks
// them to do.
func TestKMSRequestKeepsTheObservedStatus(t *testing.T) {
	for _, code := range []int{
		http.StatusServiceUnavailable, // transient: wait
		http.StatusUnauthorized,       // permanent: certificate or SAE user
		http.StatusForbidden,          // permanent
		http.StatusNotFound,           // permanent: wrong SAE path in KMS_URL
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

// The sentinel is the point of the change: callers must be able to branch
// without matching strings. main.go's ticker.Reset(KMSRetryInterval) is right
// for a 503 and wrong for a 401, and today it fires on both.
func TestExhaustedRetriesAreIdentifiableWithoutStringMatching(t *testing.T) {
	srv := busyKMS(http.StatusServiceUnavailable)
	defer srv.Close()

	_, _, err := newTestRepo(srv.URL, 1).kmsRequest("/enc_keys")
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("errors.Is(err, ErrUnavailable) is false, so a caller can "+
			"only tell by reading the message: %v", err)
	}
}

// Neither the response body nor the request path may reach the message. The
// path carries key_ID in the query string on dec_keys.
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
