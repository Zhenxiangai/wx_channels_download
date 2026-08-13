package wxmp

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wx_channel/internal/interceptor/proxy"
)

func TestOfficialAccountRequestDiagnosticOmitsSensitiveValues(t *testing.T) {
	query := url.Values{
		"__biz":       {"SENTINEL_BIZ_VALUE"},
		"key":         {"SENTINEL_KEY_VALUE"},
		"pass_ticket": {"SENTINEL_TICKET_VALUE"},
		"offset":      {"10"},
	}
	req := &proxy.ContextReq{
		URL: &proxy.ContextURL{
			Scheme:   "https",
			Path:     "/s/SENTINEL_ARTICLE_ID",
			Hostname: func() string { return "mp.weixin.qq.com" },
			RawQuery: query.Encode(),
		},
		Header: http.Header{
			"Cookie":     {"SENTINEL_COOKIE_VALUE"},
			"User-Agent": {"SENTINEL_USER_AGENT"},
		},
	}
	res := &proxy.ContextRes{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json; charset=utf-8"}},
	}

	got := official_account_request_diagnostic(req, res)
	if got == nil {
		t.Fatal("official_account_request_diagnostic() = nil")
	}
	if got.Path != "/s/:id" {
		t.Fatalf("sanitized path = %q", got.Path)
	}
	if !got.HasCookie || got.StatusCode != 200 || got.ContentType != "application/json" {
		t.Fatalf("structural metadata = %#v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, secret := range []string{
		"SENTINEL_BIZ_VALUE",
		"SENTINEL_KEY_VALUE",
		"SENTINEL_TICKET_VALUE",
		"SENTINEL_ARTICLE_ID",
		"SENTINEL_COOKIE_VALUE",
		"SENTINEL_USER_AGENT",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("diagnostic leaked %q: %s", secret, text)
		}
	}
	for _, key := range []string{"__biz", "key", "offset", "pass_ticket"} {
		if !strings.Contains(text, `"`+key+`"`) {
			t.Fatalf("diagnostic omitted query key %q: %s", key, text)
		}
	}
}

func TestOfficialAccountRequestDiagnosticRejectsOtherHosts(t *testing.T) {
	req := &proxy.ContextReq{URL: &proxy.ContextURL{
		Scheme:   "https",
		Path:     "/mp/history",
		Hostname: func() string { return "mp.weixin.qq.com.example.com" },
	}}
	if got := official_account_request_diagnostic(req, nil); got != nil {
		t.Fatalf("diagnostic = %#v, want nil", got)
	}
}

func TestAppendOfficialAccountDiagnosticUsesOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wxmp-request-diagnostics.jsonl")
	diagnostic := &officialAccountRequestDiagnostic{
		Timestamp:   123,
		Path:        "/mp/history",
		QueryKeys:   []string{"offset"},
		HasCookie:   false,
		StatusCode:  200,
		ContentType: "application/json",
	}
	if err := append_official_account_diagnostic(path, diagnostic); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SENTINEL") {
		t.Fatal("diagnostic file contained sensitive sentinel")
	}
	if !strings.Contains(string(data), `"path":"/mp/history"`) {
		t.Fatalf("diagnostic file = %s", data)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("diagnostic permissions = %o, want 600", got)
	}
}

func TestOfficialAccountDiagnosticsRequireExplicitMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wxmp-request-diagnostics.jsonl")
	if official_account_diagnostics_enabled(path) {
		t.Fatal("diagnostics enabled without marker")
	}
	marker := filepath.Join(dir, "wxmp-request-diagnostics.enabled")
	if err := os.WriteFile(marker, []byte("enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !official_account_diagnostics_enabled(path) {
		t.Fatal("diagnostics disabled with explicit marker")
	}
}
