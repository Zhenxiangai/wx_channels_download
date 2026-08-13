package wxmp

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"wx_channel/internal/interceptor/proxy"
)

type officialAccountRequestDiagnostic struct {
	Timestamp   int64    `json:"timestamp"`
	Path        string   `json:"path"`
	QueryKeys   []string `json:"query_keys,omitempty"`
	HasCookie   bool     `json:"has_cookie"`
	StatusCode  int      `json:"status_code,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
}

var official_account_diagnostic_mu sync.Mutex

func official_account_diagnostics_enabled(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	marker := filepath.Join(filepath.Dir(path), "wxmp-request-diagnostics.enabled")
	info, err := os.Stat(marker)
	return err == nil && !info.IsDir() && info.Mode().Perm()&0o077 == 0
}

func sanitize_official_account_path(path string) string {
	if path == "/s" || strings.HasPrefix(path, "/s/") {
		return "/s/:id"
	}
	if path == "" || !strings.HasPrefix(path, "/") || len(path) > 256 {
		return "/:other"
	}
	for _, r := range path {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("/-_.", r) {
			continue
		}
		return "/:other"
	}
	return path
}

func sanitize_official_account_query_keys(raw string) []string {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if key == "" || len(key) > 64 {
			continue
		}
		safe := true
		for _, r := range key {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
				continue
			}
			safe = false
			break
		}
		if safe {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > 64 {
		keys = keys[:64]
	}
	return keys
}

func normalized_official_account_content_type(header http.Header) string {
	if header == nil {
		return ""
	}
	contentType := strings.TrimSpace(header.Get("Content-Type"))
	if index := strings.IndexByte(contentType, ';'); index >= 0 {
		contentType = contentType[:index]
	}
	if len(contentType) > 96 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

func official_account_request_diagnostic(req *proxy.ContextReq, res *proxy.ContextRes) *officialAccountRequestDiagnostic {
	if req == nil || req.URL == nil || !strings.EqualFold(req.URL.Scheme, "https") ||
		!strings.EqualFold(req.URL.Hostname(), "mp.weixin.qq.com") {
		return nil
	}
	diagnostic := &officialAccountRequestDiagnostic{
		Timestamp: time.Now().UnixMilli(),
		Path:      sanitize_official_account_path(req.URL.Path),
		QueryKeys: sanitize_official_account_query_keys(req.URL.RawQuery),
		HasCookie: req.Header != nil && strings.TrimSpace(req.Header.Get("Cookie")) != "",
	}
	if res != nil {
		diagnostic.StatusCode = res.StatusCode
		diagnostic.ContentType = normalized_official_account_content_type(res.Header)
	}
	return diagnostic
}

func append_official_account_diagnostic(path string, diagnostic *officialAccountRequestDiagnostic) error {
	if strings.TrimSpace(path) == "" || diagnostic == nil {
		return nil
	}
	data, err := json.Marshal(diagnostic)
	if err != nil {
		return err
	}
	official_account_diagnostic_mu.Lock()
	defer official_account_diagnostic_mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	return err
}
