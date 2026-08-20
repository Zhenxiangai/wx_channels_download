package wxmp

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wx_channel/frontend"
	"wx_channel/internal/interceptor"
	"wx_channel/internal/interceptor/proxy"
)

var csp_nonce_reg = regexp.MustCompile(`'nonce-([^']+)'`)

type OfficialAccountArticleProfile struct {
	UniqueMark    string          `json:"unique_mark"`
	Title         string          `json:"title"`
	URL           string          `json:"url"`
	SourceURL     string          `json:"source_url"`
	CoverURL      string          `json:"cover_url"`
	Biz           string          `json:"biz"`
	Username      string          `json:"username"`
	Nickname      string          `json:"nickname"`
	AvatarURL     string          `json:"avatar_url"`
	Mid           string          `json:"mid"`
	Idx           string          `json:"idx"`
	Sn            string          `json:"sn"`
	RawCgiDataNew json.RawMessage `json:"cgiDataNew"`
}

func NewOfficialAccountArticleProfile(raw json.RawMessage) (*OfficialAccountArticleProfile, error) {
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}

	profile := &OfficialAccountArticleProfile{
		Title:         json_string(data, "title"),
		URL:           html.UnescapeString(json_string(data, "link")),
		SourceURL:     html.UnescapeString(json_string(data, "source_url")),
		CoverURL:      html.UnescapeString(json_string(data, "cdn_url")),
		Biz:           json_string(data, "bizuin"),
		Username:      json_string(data, "user_name"),
		Nickname:      json_string(data, "nick_name"),
		AvatarURL:     html.UnescapeString(first_official_account_value(json_string(data, "round_head_img"), json_string(data, "ori_head_img_url"), json_string(data, "hd_head_img"))),
		Mid:           json_scalar_string(data, "mid"),
		Idx:           json_scalar_string(data, "idx"),
		Sn:            json_string(data, "sn"),
		RawCgiDataNew: raw,
	}
	fill_official_account_article_from_url(profile)
	profile.UniqueMark = build_official_account_article_unique_mark(profile)
	return profile, nil
}

func fill_official_account_article_from_url(profile *OfficialAccountArticleProfile) {
	if profile == nil || profile.URL == "" {
		return
	}
	u, err := url.Parse(profile.URL)
	if err != nil {
		return
	}
	query := u.Query()
	if profile.Biz == "" {
		profile.Biz = query.Get("__biz")
	}
	if profile.Mid == "" {
		profile.Mid = query.Get("mid")
	}
	if profile.Idx == "" {
		profile.Idx = query.Get("idx")
	}
	if profile.Sn == "" {
		profile.Sn = query.Get("sn")
	}
}

func build_official_account_article_unique_mark(profile *OfficialAccountArticleProfile) string {
	parts := []string{profile.Biz, profile.Mid, profile.Idx, profile.Sn}
	all_present := true
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			all_present = false
			break
		}
	}
	if all_present {
		return strings.Join(parts, "_")
	}
	return first_official_account_value(profile.URL, profile.SourceURL, profile.Title)
}

func json_string(data map[string]json.RawMessage, key string) string {
	raw, ok := data[key]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

func json_scalar_string(data map[string]json.RawMessage, key string) string {
	if s := json_string(data, key); s != "" {
		return s
	}
	raw, ok := data[key]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return fmt.Sprintf("%t", b)
	}
	return ""
}

func first_official_account_value(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func official_account_credential_from_request(req *proxy.ContextReq) *OfficialAccount {
	if req == nil || req.URL == nil || !strings.EqualFold(req.URL.Scheme, "https") ||
		!strings.EqualFold(req.URL.Hostname(), "mp.weixin.qq.com") {
		return nil
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return nil
	}
	is_profile_request := req.URL.Path == "/mp/profile_ext"
	is_article_request := req.URL.Path == "/s" || strings.HasPrefix(req.URL.Path, "/s/")
	is_cookie_less_session_probe := req.URL.Path == "/mp/relatedsearchword"
	if !is_profile_request && !is_article_request && !is_cookie_less_session_probe {
		return nil
	}
	if is_profile_request {
		action := strings.TrimSpace(query.Get("action"))
		if action != "home" && action != "getmsg" {
			return nil
		}
	}
	biz := strings.TrimSpace(query.Get("__biz"))
	uin := strings.TrimSpace(query.Get("uin"))
	key := strings.TrimSpace(query.Get("key"))
	pass_ticket := strings.TrimSpace(query.Get("pass_ticket"))
	appmsg_token := ""
	if is_cookie_less_session_probe {
		appmsg_token = strings.TrimSpace(query.Get("appmsg_token"))
	}
	if biz == "" || uin == "" || key == "" {
		return nil
	}
	if is_cookie_less_session_probe && (pass_ticket == "" || appmsg_token == "" ||
		strings.TrimSpace(query.Get("mid")) == "" || strings.TrimSpace(query.Get("idx")) == "" ||
		strings.TrimSpace(query.Get("sessionid")) == "") {
		return nil
	}
	cookie := ""
	if req.Header != nil {
		cookie = strings.TrimSpace(req.Header.Get("Cookie"))
	}
	if cookie == "" && !is_cookie_less_session_probe {
		return nil
	}
	refresh_query := url.Values{"action": {"home"}, "__biz": {biz}}
	credential := &OfficialAccount{
		Biz:         biz,
		Uin:         uin,
		Key:         key,
		PassTicket:  pass_ticket,
		AppmsgToken: appmsg_token,
		Cookie:      cookie,
		RefreshUri:  "https://mp.weixin.qq.com/mp/profile_ext?" + refresh_query.Encode(),
	}
	if cookie != "" {
		credential.CookieExpiration = time.Now().Add(24 * time.Hour).Unix()
	}
	return credential
}

func CreateOfficialAccountInterceptorPlugin(cfg *OfficialAccountConfig, version string, clients ...*OfficialAccountClient) *proxy.Plugin {
	var client *OfficialAccountClient
	if len(clients) > 0 {
		client = clients[0]
	}
	asset_base_url := "/__assets"
	url_build := frontend.NewURLBuild(asset_base_url, nil)
	asset_version := version
	if asset_version == "" {
		asset_version = "static"
	}
	version_query := url.Values{"v": []string{asset_version}}
	diagnostic_path := ""
	if cfg != nil && cfg.WorkDir != "" {
		diagnostic_path = filepath.Join(cfg.WorkDir, "wxmp-request-diagnostics.jsonl")
	}
	return &proxy.Plugin{
		Match: "qq.com",
		OnRequest: func(ctx proxy.Context) {
			req := ctx.Req()
			if credential := official_account_credential_from_request(req); credential != nil && client != nil {
				client.store_credential(credential)
			}
			if req.URL.Hostname() != "mp.weixin.qq.com" {
				return
			}
			interceptor.MockFrontendStaticAsset(ctx, req.URL.Path, interceptor.FrontendStaticAssetMockOptions{
				PlatformPrefix: StaticAssetsPath + "/",
				PlatformFS:     Assets.InjectFS,
				UserScriptPath: cfg.GlobalScriptPath,
			})
		},
		OnResponse: func(ctx proxy.Context) {
			if official_account_diagnostics_enabled(diagnostic_path) {
				if diagnostic := official_account_request_diagnostic(ctx.Req(), ctx.Res()); diagnostic != nil {
					_ = append_official_account_diagnostic(diagnostic_path, diagnostic)
				}
			}
			resp_content_type := strings.ToLower(ctx.GetResponseHeader("Content-Type"))
			hostname := ctx.Req().URL.Hostname()
			// pathname := ctx.Req().URL.Path
			if cfg.Enabled && hostname == "mp.weixin.qq.com" && strings.Contains(resp_content_type, "text/html") {
				resp_body, err := ctx.GetResponseBody()
				if err != nil {
					return
				}
				html := string(resp_body)
				csp := ctx.GetResponseHeader("Content-Security-Policy") + " " + ctx.GetResponseHeader("Content-Security-Policy-Report-Only")
				interceptor.RewriteResponseCSPForLocalAssets(ctx, asset_base_url)
				variables := build_official_account_variables(html)
				script_attr := ""
				style_attr := ""
				if match := csp_nonce_reg.FindStringSubmatch(csp); len(match) > 1 {
					script_attr = fmt.Sprintf(` nonce="%s" reportloaderror`, match[1])
					style_attr = fmt.Sprintf(` nonce="%s"`, match[1])
				}
				var injected strings.Builder
				if cfg.DebugShowError {
					/** Global error capture and show dialog */
					frontend.AppendScripts(&injected, script_attr, url_build("/inject/error.js", version_query))
				}
				frontend.AppendScripts(&injected, script_attr, url_build("/public/timeless/0.30.0/timeless.umd.min.js", version_query))
				frontend.AppendScripts(&injected, script_attr, url_build("/public/timeless/0.30.0/timeless.utils.umd.min.js", version_query))
				frontend.AppendStylesheets(&injected, style_attr, url_build("/public/timeless/0.30.0/timeless.weui.css", version_query))
				frontend.AppendScripts(&injected, script_attr, url_build("/public/timeless/0.30.0/timeless.weui.umd.min.js", version_query))
				frontend.AppendScripts(&injected, script_attr, url_build("/public/timeless/0.30.0/timeless.dom.umd.min.js", version_query))
				frontend.AppendScripts(&injected, script_attr, url_build("/public/timeless/0.30.0/timeless.web.umd.min.js", version_query))
				frontend.AppendStylesheets(&injected, style_attr, url_build("/inject/components.css"))
				frontend_config := make(map[string]any, len(variables)+2)
				cfg_byte, _ := json.Marshal(cfg)
				_ = json.Unmarshal(cfg_byte, &frontend_config)
				for key, value := range variables {
					frontend_config[key] = value
				}
				frontend_config["version"] = version
				frontend_config["assets_base_url"] = asset_base_url
				frontend_config_byte, _ := json.Marshal(frontend_config)
				frontend.AppendInlineScript(
					&injected,
					script_attr,
					fmt.Sprintf(`window.__d_config = %s;`, frontend_config_byte),
				)
				frontend.AppendScripts(
					&injected,
					script_attr,
					url_build("/public/mitt.umd.js"),
					url_build("/inject/eventbus.js", version_query),
					url_build("/inject/env.js", version_query),
					url_build("/inject/utils.js", version_query),
					url_build("/inject/components.js", version_query),
					url_build("/inject/virtual-list-view.js", version_query),
					url_build("/inject/download/model.js", version_query),
					url_build("/inject/download/view.js", version_query),
					AssetURL(asset_base_url, "/inject/mp.ws.js", version_query),
				)
				if cfg.GlobalScriptURL != "" {
					frontend.AppendScripts(&injected, script_attr, cfg.GlobalScriptURL)
				}
				if cfg.InjectContentScript != "" {
					frontend.AppendInlineScript(&injected, script_attr, cfg.InjectContentScript)
				}
				html = strings.Replace(html, "</body>", injected.String()+"</body>", 1)
				ctx.SetResponseBody(html)
				return
			}
		},
	}
}
