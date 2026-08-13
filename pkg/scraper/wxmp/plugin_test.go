package wxmp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"testing"

	"wx_channel/internal/interceptor/proxy"
)

func TestOfficialAccountCredentialFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		action     string
		passTicket string
	}{
		{name: "home", action: "home"},
		{name: "getmsg with pass ticket", action: "getmsg", passTicket: "pass-secret"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := url.Values{
				"action": {test.action},
				"__biz":  {"biz-id"},
				"uin":    {"uin-secret"},
				"key":    {"key-secret"},
				"extra":  {"ignored"},
			}
			if test.passTicket != "" {
				query.Set("pass_ticket", test.passTicket)
			}
			got := official_account_credential_from_request(test_context_request("https", "mp.weixin.qq.com", "/mp/profile_ext", query))
			if got == nil {
				t.Fatal("official_account_credential_from_request() = nil")
			}
			if got.Biz != "biz-id" || got.Uin != "uin-secret" || got.Key != "key-secret" || got.PassTicket != test.passTicket || got.Cookie != "session=cookie-secret" {
				t.Fatal("captured credential metadata does not match request")
			}
			if got.CookieExpiration <= 0 {
				t.Fatal("captured credential cookie expiration was not set")
			}
			refresh, err := url.Parse(got.RefreshUri)
			if err != nil {
				t.Fatalf("parse refresh URI: %v", err)
			}
			if refresh.Scheme != "https" || refresh.Host != "mp.weixin.qq.com" || refresh.Path != "/mp/profile_ext" {
				t.Fatalf("refresh URI location = %q", got.RefreshUri)
			}
			if values := refresh.Query(); len(values) != 2 || values.Get("action") != "home" || values.Get("__biz") != "biz-id" {
				t.Fatalf("sanitized refresh query = %v", values)
			}
		})
	}
}

func TestOfficialAccountCredentialFromCurrentMacArticleRequest(t *testing.T) {
	query := url.Values{
		"__biz":       {"biz-id"},
		"uin":         {"uin-secret"},
		"key":         {"key-secret"},
		"pass_ticket": {"pass-secret"},
		"mid":         {"article-mid"},
		"idx":         {"1"},
	}
	got := official_account_credential_from_request(test_context_request("https", "mp.weixin.qq.com", "/s/article-id", query))
	if got == nil {
		t.Fatal("official_account_credential_from_request() = nil for complete article request")
	}
	if got.Biz != "biz-id" || got.Uin != "uin-secret" || got.Key != "key-secret" || got.PassTicket != "pass-secret" || got.Cookie != "session=cookie-secret" {
		t.Fatal("captured article credential metadata does not match request")
	}
	if got.RefreshUri != "https://mp.weixin.qq.com/mp/profile_ext?__biz=biz-id&action=home" {
		t.Fatalf("persisted refresh URI was not sanitized: %q", got.RefreshUri)
	}
}

func TestOfficialAccountCredentialFromArticleRejectsMissingCookie(t *testing.T) {
	query := url.Values{"__biz": {"biz-id"}, "uin": {"uin-secret"}, "key": {"key-secret"}}
	req := test_context_request("https", "mp.weixin.qq.com", "/s/article-id", query)
	req.Header.Del("Cookie")
	if got := official_account_credential_from_request(req); got != nil {
		t.Fatal("article request without cookie returned credential")
	}
}

func TestOfficialAccountClientStoresCapturedCredential(t *testing.T) {
	old_path := mp_json_filepath
	acct_mu.Lock()
	old_accounts := accounts
	accounts = make(map[string]*OfficialAccount)
	acct_mu.Unlock()
	mp_json_filepath = t.TempDir() + "/mp.json"
	t.Cleanup(func() {
		acct_mu.Lock()
		accounts = old_accounts
		acct_mu.Unlock()
		mp_json_filepath = old_path
	})

	query := url.Values{"action": {"getmsg"}, "__biz": {"biz-id"}, "uin": {"uin-secret"}, "key": {"key-secret"}, "pass_ticket": {"pass-secret"}}
	credential := official_account_credential_from_request(test_context_request("https", "mp.weixin.qq.com", "/mp/profile_ext", query))
	client := &OfficialAccountClient{wait_chan_map: make(map[string]chan *OfficialAccount)}
	client.store_credential(credential)

	data, err := os.ReadFile(mp_json_filepath)
	if err != nil {
		t.Fatalf("read persisted accounts: %v", err)
	}
	var persisted map[string]*OfficialAccount
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("decode persisted accounts: %v", err)
	}
	got := persisted["biz-id"]
	if got == nil || got.Uin != "uin-secret" || got.Key != "key-secret" || got.PassTicket != "pass-secret" || got.Cookie != "session=cookie-secret" {
		t.Fatal("persisted credential metadata does not match request")
	}
	if got.RefreshUri != "https://mp.weixin.qq.com/mp/profile_ext?__biz=biz-id&action=home" {
		t.Fatalf("persisted refresh URI was not sanitized: %q", got.RefreshUri)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(mp_json_filepath)
		if err != nil {
			t.Fatalf("stat persisted accounts: %v", err)
		}
		if gotMode := info.Mode().Perm(); gotMode != 0o600 {
			t.Fatalf("persisted credential permissions = %o, want 600", gotMode)
		}
	}
}

func TestOfficialAccountClientFetchReplaysCapturedCookie(t *testing.T) {
	seen := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ret":0}`))
	}))
	defer server.Close()

	client := &OfficialAccountClient{}
	response, err := client.Fetch(server.URL, "https://mp.weixin.qq.com/", "session=cookie-secret")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	response.Body.Close()
	if seen != "session=cookie-secret" {
		t.Fatal("Fetch() did not replay captured cookie")
	}
}

func TestBuildOfficialArticleRequestRequiresExactHostAndMatchingBiz(t *testing.T) {
	acct := &OfficialAccount{Biz: "biz-id", Uin: "uin-secret", Key: "key-secret", PassTicket: "pass-secret", Cookie: "session=cookie-secret"}
	tests := []string{
		"http://mp.weixin.qq.com/s?__biz=biz-id&mid=1&idx=1&sn=x",
		"https://example.com/s?__biz=biz-id&mid=1&idx=1&sn=x",
		"https://mp.weixin.qq.com.example.com/s?__biz=biz-id&mid=1&idx=1&sn=x",
		"https://mp.weixin.qq.com/other?__biz=biz-id&mid=1&idx=1&sn=x",
		"https://mp.weixin.qq.com/s?__biz=other-biz&mid=1&idx=1&sn=x",
	}
	for _, target := range tests {
		if _, err := build_official_article_request(target, acct); err == nil {
			t.Fatalf("build_official_article_request(%q) succeeded, want rejection", target)
		}
	}
}

func TestBuildOfficialArticleRequestAddsSessionWithoutChangingArticleIdentity(t *testing.T) {
	acct := &OfficialAccount{Biz: "biz-id", Uin: "uin-secret", Key: "key-secret", PassTicket: "pass-secret", Cookie: "session=cookie-secret"}
	req, err := build_official_article_request("https://mp.weixin.qq.com/s?__biz=biz-id&mid=article-mid&idx=2&sn=article-sn", acct)
	if err != nil {
		t.Fatalf("build_official_article_request() error = %v", err)
	}
	query := req.URL.Query()
	if query.Get("__biz") != "biz-id" || query.Get("mid") != "article-mid" || query.Get("idx") != "2" || query.Get("sn") != "article-sn" {
		t.Fatal("article identity changed")
	}
	if query.Get("uin") != "uin-secret" || query.Get("key") != "key-secret" || query.Get("pass_ticket") != "pass-secret" {
		t.Fatal("captured session fields were not added")
	}
	if req.Header.Get("Cookie") != "session=cookie-secret" {
		t.Fatal("captured Cookie was not replayed")
	}
}

func TestRedactOfficialArticleSessionRemovesCapturedValues(t *testing.T) {
	acct := &OfficialAccount{Uin: "uin-secret", Key: "key-secret", PassTicket: "pass-secret", AppmsgToken: "token-secret", Cookie: "session=cookie-secret; other=other-secret"}
	body := []byte(`uin-secret key-secret pass-secret token-secret cookie-secret other-secret preserved`)
	got := redact_official_article_session(body, acct)
	for _, secret := range []string{"uin-secret", "key-secret", "pass-secret", "token-secret", "cookie-secret", "other-secret"} {
		if bytes.Contains(got, []byte(secret)) {
			t.Fatalf("redacted body still contains captured session value")
		}
	}
	if !bytes.Contains(got, []byte("preserved")) {
		t.Fatal("redaction modified unrelated content")
	}
}

func TestOfficialAccountCredentialFromRequestIgnoresUnrelatedOrIncompleteRequests(t *testing.T) {
	valid := url.Values{"action": {"home"}, "__biz": {"biz-id"}, "uin": {"uin-secret"}, "key": {"key-secret"}}
	tests := []struct {
		name   string
		scheme string
		host   string
		path   string
		query  url.Values
	}{
		{name: "http", scheme: "http", host: "mp.weixin.qq.com", path: "/mp/profile_ext", query: valid},
		{name: "other host", scheme: "https", host: "example.com", path: "/mp/profile_ext", query: valid},
		{name: "host suffix", scheme: "https", host: "mp.weixin.qq.com.example.com", path: "/mp/profile_ext", query: valid},
		{name: "other path", scheme: "https", host: "mp.weixin.qq.com", path: "/other", query: valid},
		{name: "other action", scheme: "https", host: "mp.weixin.qq.com", path: "/mp/profile_ext", query: url.Values{"action": {"list"}, "__biz": {"biz-id"}, "uin": {"uin-secret"}, "key": {"key-secret"}}},
		{name: "missing biz", scheme: "https", host: "mp.weixin.qq.com", path: "/mp/profile_ext", query: url.Values{"action": {"home"}, "uin": {"uin-secret"}, "key": {"key-secret"}}},
		{name: "missing uin", scheme: "https", host: "mp.weixin.qq.com", path: "/mp/profile_ext", query: url.Values{"action": {"home"}, "__biz": {"biz-id"}, "key": {"key-secret"}}},
		{name: "missing key", scheme: "https", host: "mp.weixin.qq.com", path: "/mp/profile_ext", query: url.Values{"action": {"home"}, "__biz": {"biz-id"}, "uin": {"uin-secret"}}},
		{name: "empty key", scheme: "https", host: "mp.weixin.qq.com", path: "/mp/profile_ext", query: url.Values{"action": {"home"}, "__biz": {"biz-id"}, "uin": {"uin-secret"}, "key": {""}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := official_account_credential_from_request(test_context_request(test.scheme, test.host, test.path, test.query)); got != nil {
				t.Fatal("official_account_credential_from_request() returned credential, want nil")
			}
		})
	}
}

func test_context_request(scheme, host, path string, query url.Values) *proxy.ContextReq {
	return &proxy.ContextReq{URL: &proxy.ContextURL{
		Scheme:   scheme,
		Path:     path,
		Hostname: func() string { return host },
		RawQuery: query.Encode(),
	}, Header: http.Header{"Cookie": {"session=cookie-secret"}}}
}
