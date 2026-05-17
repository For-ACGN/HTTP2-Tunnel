package h2tunnel

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

type reverseProxy struct {
	filter []string
	target *url.URL
	proxy  *httputil.ReverseProxy
}

func newReverseProxy(logger *logger, URL string, filter []string) (http.Handler, error) {
	target, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}
	rp := &reverseProxy{
		target: target,
		filter: filter,
	}
	proxy := new(httputil.ReverseProxy)
	proxy.Rewrite = func(r *httputil.ProxyRequest) {
		r.SetURL(target)
		// strip sensitive headers to prevent cookie/credential leakage
		header := r.Out.Header
		header.Del("Cookie")
		header.Del("Authorization")
		header.Del("Proxy-Authorization")
		// strip custom headers
		for _, key := range rp.filter {
			header.Del(key)
		}
		r.SetXForwarded()
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		// strip sensitive headers to prevent cookie/credential leakage
		header := resp.Header
		header.Del("Set-Cookie")
		header.Del("Authorization")
		// strip custom headers
		for _, key := range rp.filter {
			header.Del(key)
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusBadGateway)
		logger.Error("occur when reverse proxy:", err)
	}
	rp.proxy = proxy
	return rp, nil
}

func (rp *reverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rp.proxy.ServeHTTP(w, r)
}
