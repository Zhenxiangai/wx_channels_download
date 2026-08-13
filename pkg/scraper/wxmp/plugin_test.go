package wxmp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"

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
	acct := &OfficialAccount{Uin: "uin-secret", Key: "key+secret/value", PassTicket: "pass&secret", AppmsgToken: "token-secret", Cookie: "session=cookie+secret/value; other=other&secret"}
	body := []byte(`uin-secret key+secret/value key%2Bsecret%2Fvalue pass&amp;secret pass%26secret pass%26amp%3Bsecret token-secret cookie%2Bsecret%2Fvalue other&amp;secret preserved`)
	got := redact_official_article_session(body, acct)
	for _, secret := range []string{
		"uin-secret",
		"key+secret/value",
		"key%2Bsecret%2Fvalue",
		"pass&amp;secret",
		"pass%26secret",
		"pass%26amp%3Bsecret",
		"token-secret",
		"cookie%2Bsecret%2Fvalue",
		"other&amp;secret",
	} {
		if bytes.Contains(got, []byte(secret)) {
			t.Fatalf("redacted body still contains captured session value or encoded variant")
		}
	}
	if !bytes.Contains(got, []byte("preserved")) {
		t.Fatal("redaction modified unrelated content")
	}
}

func TestOfficialArticleRedirectPolicyRejectsUnsafeTargets(t *testing.T) {
	via := []*http.Request{{URL: &url.URL{Scheme: "https", Host: "mp.weixin.qq.com", Path: "/s", RawQuery: "__biz=biz-id&mid=1&idx=1&sn=origin"}}}
	for _, target := range []string{
		"http://mp.weixin.qq.com/s?__biz=biz-id&mid=2&idx=1&sn=next",
		"https://example.com/s?__biz=biz-id&mid=2&idx=1&sn=next",
		"https://mp.weixin.qq.com.example.com/s?__biz=biz-id&mid=2&idx=1&sn=next",
		"https://mp.weixin.qq.com/other?__biz=biz-id&mid=2&idx=1&sn=next",
		"https://mp.weixin.qq.com/s?__biz=other-biz&mid=2&idx=1&sn=next",
		"https://mp.weixin.qq.com/s?__biz=biz-id",
		"https://mp.weixin.qq.com/s?__biz=biz-id&mid=2&idx=1",
	} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := official_article_redirect_policy(req, via); err == nil {
			t.Fatalf("redirect to %q succeeded, want rejection", target)
		}
	}
}

func TestOfficialArticleRedirectPolicyAllowsBoundedSameHostArticleRedirect(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://mp.weixin.qq.com/s/next?__biz=biz-id&mid=2&idx=1&sn=next", nil)
	via := []*http.Request{{URL: &url.URL{Scheme: "https", Host: "mp.weixin.qq.com", Path: "/s", RawQuery: "__biz=biz-id&mid=1&idx=1&sn=origin"}}}
	if err := official_article_redirect_policy(req, via); err != nil {
		t.Fatalf("same-host article redirect rejected: %v", err)
	}
	tooMany := make([]*http.Request, 5)
	if err := official_article_redirect_policy(req, tooMany); err == nil {
		t.Fatal("redirect chain longer than limit succeeded")
	}
}

func TestHandleFetchOfficialArticleRejectsNonLoopbackClient(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/mp/article/content?url=https%3A%2F%2Fmp.weixin.qq.com%2Fs%3F__biz%3Dbiz-id%26mid%3D1%26idx%3D1%26sn%3Dx", nil)
	request.RemoteAddr = "192.0.2.10:4567"
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request
	(&OfficialAccountClient{}).HandleFetchOfficialArticle(ctx)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestHandleFetchOfficialArticleRejectsBrowserOriginAndMissingLocalHeader(t *testing.T) {
	for _, mutate := range []func(*http.Request){
		func(request *http.Request) { request.Header.Set("Origin", "https://attacker.example") },
		func(request *http.Request) {},
	} {
		request := httptest.NewRequest(http.MethodGet, "/api/mp/article/content?url=https%3A%2F%2Fmp.weixin.qq.com%2Fs%3F__biz%3Dbiz-id%26mid%3D1%26idx%3D1%26sn%3Dx", nil)
		request.RemoteAddr = "127.0.0.1:4567"
		mutate(request)
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = request
		(&OfficialAccountClient{}).HandleFetchOfficialArticle(ctx)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
		}
	}
}

func TestOfficialArticleLocalRequestAllowsNonBrowserCaller(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "[::1]:4567"
	request.Header.Set("X-WXMP-Local-Client", "1")
	if !is_trusted_local_article_request(request) {
		t.Fatal("trusted local non-browser request was rejected")
	}
}

func TestAtomicWriteOwnerOnlyReplacesExistingFile(t *testing.T) {
	path := t.TempDir() + "/mp.json"
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomic_write_owner_only(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("file = %q, want new", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %o, want 600", info.Mode().Perm())
		}
	}
	matches, err := filepath.Glob(path + ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func TestAtomicWriteOwnerOnlyPreservesExistingFileOnReplaceFailure(t *testing.T) {
	path := t.TempDir() + "/mp.json"
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := replace_file_atomically
	replace_file_atomically = func(string, string) error { return errors.New("replace failed") }
	t.Cleanup(func() { replace_file_atomically = original })
	if err := atomic_write_owner_only(path, []byte("new")); err == nil {
		t.Fatal("atomic write succeeded, want replacement failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("existing file = %q, want old", got)
	}
	matches, err := filepath.Glob(path + ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain after failure: %v", matches)
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
