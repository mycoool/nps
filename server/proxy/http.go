package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego"
	"github.com/caddyserver/certmagic"
	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/conn"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/goroutine"
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/server/connection"
)

type httpServer struct {
	BaseServer
	httpPort      int
	httpsPort     int
	httpServer    *http.Server
	httpsServer   *http.Server
	httpsListener net.Listener
	httpOnlyPass  string
	addOrigin     bool
	httpPortStr   string
	httpsPortStr  string
	magic         *certmagic.Config
	acme          *certmagic.ACMEIssuer
}

func NewHttp(bridge NetBridge, task *file.Tunnel, httpPort, httpsPort int, httpOnlyPass string, addOrigin bool) *httpServer {
	allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy")
	return &httpServer{
		BaseServer: BaseServer{
			task:            task,
			bridge:          bridge,
			allowLocalProxy: allowLocalProxy,
			Mutex:           sync.Mutex{},
		},
		httpPort:     httpPort,
		httpsPort:    httpsPort,
		httpOnlyPass: httpOnlyPass,
		addOrigin:    addOrigin,
		httpPortStr:  strconv.Itoa(httpPort),
		httpsPortStr: strconv.Itoa(httpsPort),
	}
}

func (s *httpServer) Start() error {
	var err error
	s.errorContent, err = common.ReadAllFromFile(filepath.Join(common.GetRunPath(), "web", "static", "page", "error.html"))
	if err != nil {
		s.errorContent = []byte("nps 404")
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = beego.AppConfig.String("ssl_email")
	switch strings.ToLower(beego.AppConfig.DefaultString("ssl_ca", "LetsEncrypt")) {
	case "letsencrypt", "le", "prod", "production":
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	case "zerossl", "zero", "zs":
		certmagic.DefaultACME.CA = certmagic.ZeroSSLProductionCA
	case "googletrust", "google", "goog":
		certmagic.DefaultACME.CA = certmagic.GoogleTrustProductionCA
	default:
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}
	certmagic.Default.Storage = &certmagic.FileStorage{
		Path: common.ResolvePath(beego.AppConfig.DefaultString("ssl_path", "ssl")),
	}
	s.magic = certmagic.NewDefault()
	if certmagic.DefaultACME.CA == certmagic.ZeroSSLProductionCA {
		s.magic.Issuers = []certmagic.Issuer{
			&certmagic.ZeroSSLIssuer{
				APIKey: beego.AppConfig.String("ssl_zerossl_api"),
			},
		}
	}
	s.magic.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			h, err := file.GetDb().FindCertByHost(name)
			if err != nil {
				return fmt.Errorf("unknown host %q", name)
			}
			if !h.AutoSSL {
				return fmt.Errorf("AutoSSL disabled for %q", name)
			}
			return nil
		},
	}
	s.acme = certmagic.NewACMEIssuer(s.magic, certmagic.DefaultACME)

	if s.httpPort > 0 {
		s.httpServer = s.NewServer(s.httpPort, "http")
		go func() {
			l, err := connection.GetHttpListener()
			if err != nil {
				logs.Error("Failed to start HTTP listener: %v", err)
				os.Exit(0)
			}
			logs.Info("HTTP server listening on port %d", s.httpPort)
			if err := s.httpServer.Serve(l); err != nil {
				logs.Error("HTTP server stopped: %v", err)
				os.Exit(0)
			}
		}()
	}

	if s.httpsPort > 0 {
		s.httpsServer = s.NewServer(s.httpsPort, "https")
		go func() {
			s.httpsListener, err = connection.GetHttpsListener()
			if err != nil {
				logs.Error("Failed to start HTTPS listener: %v", err)
				os.Exit(0)
			}
			logs.Info("HTTPS server listening on port %d", s.httpsPort)
			if err := NewHttpsServer(s.httpsListener, s.bridge, s.task, s.httpsServer, s.magic).Start(); err != nil {
				logs.Error("HTTPS server stopped: %v", err)
				os.Exit(0)
			}
		}()
	}
	return nil
}

func (s *httpServer) Close() error {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	if s.httpsServer != nil {
		s.httpsServer.Close()
	}
	if s.httpsListener != nil {
		s.httpsListener.Close()
	}
	return nil
}

func (s *httpServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Get host
	host, err := file.GetDb().GetInfoByHost(r.Host, r)
	if err != nil {
		//http.Error(w, "404 Host not found", http.StatusNotFound)
		//w.Header().Set("Content-Type", "text/html; charset=utf-8")
		//w.WriteHeader(http.StatusNotFound)
		//w.Write(s.errorContent)
		logs.Debug("Host not found: %s %s %s", r.URL.Scheme, r.Host, r.RequestURI)
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
		return
	}

	// IP Black List
	clientIP := common.GetIpByAddr(r.RemoteAddr)
	if IsGlobalBlackIp(clientIP) || common.IsBlackIp(clientIP, host.Client.VerifyKey, host.Client.BlackIpList) {
		//http.Error(w, "403 Forbidden", http.StatusForbidden)
		logs.Warn("Blocked IP: %s", clientIP)
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
		return
	}

	// AutoSSL
	if host.AutoSSL && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") && (s.httpPort == 80 || s.httpsPort == 443) {
		s.acme.HandleHTTPChallenge(w, r)
		return
	}

	// Path Rewrite
	if host.PathRewrite != "" && strings.HasPrefix(r.URL.Path, host.Location) {
		r.Header.Set("X-Original-Path", r.URL.Path)
		r.URL.Path = host.PathRewrite + r.URL.Path[len(host.Location):]
	}

	// HTTP-Only
	isHttpOnlyRequest := (s.httpOnlyPass != "" && r.Header.Get("X-NPS-Http-Only") == s.httpOnlyPass)
	if isHttpOnlyRequest {
		r.Header.Del("X-NPS-Http-Only")
	}

	// Auto 301 to HTTPS
	if !isHttpOnlyRequest && host.AutoHttps && r.TLS == nil {
		redirectHost := common.RemovePortFromHost(r.Host)
		if s.httpsPort != 443 {
			redirectHost += ":" + s.httpsPortStr
		}
		http.Redirect(w, r, "https://"+redirectHost+r.RequestURI, http.StatusMovedPermanently)
		return
	}

	// Check flow and conn
	if err := s.CheckFlowAndConnNum(host.Client); err != nil {
		http.Error(w, "Access denied: "+err.Error(), http.StatusTooManyRequests)
		logs.Warn("Connection limit exceeded, client id %d, host id %d, error %v", host.Client.Id, host.Id, err)
		return
	}
	defer host.Client.CutConn()

	// HTTP Auth
	if r.Header.Get("Upgrade") == "" {
		if err := s.auth(r, nil, host.Client.Cnf.U, host.Client.Cnf.P, s.task.MultiAccount, host.UserAuth); err != nil {
			logs.Warn("Unauthorized request from %s", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Get target addr
	targetAddr, err := host.Target.GetRandomTarget()
	if err != nil {
		logs.Warn("No backend found for host: %s Err: %v", r.Host, err)
		//http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write(s.errorContent)
		return
	}

	logs.Debug("%s request, method %s, host %s, url %s, remote address %s, target %s", r.URL.Scheme, r.Method, r.Host, r.URL.Path, r.RemoteAddr, targetAddr)

	// WebSocket
	if r.Method == "CONNECT" || r.Header.Get("Upgrade") != "" || r.Header.Get(":protocol") != "" {
		s.handleWebsocket(w, r, host, targetAddr, isHttpOnlyRequest)
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			//req = req.WithContext(context.WithValue(req.Context(), "origReq", r))
			if host.TargetIsHttps {
				req.URL.Scheme = "https"
			} else {
				req.URL.Scheme = "http"
			}
			req.URL.Host = r.Host
			//logs.Debug("Director: set req.URL.Scheme=%s, req.URL.Host=%s", req.URL.Scheme, req.URL.Host)
			common.ChangeHostAndHeader(req, host.HostChange, host.HeaderChange, isHttpOnlyRequest)
			if isHttpOnlyRequest {
				req.Header["X-Forwarded-For"] = nil
			}
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: 60 * time.Second,
			DisableKeepAlives:     true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName: func() string {
					if host.TargetIsHttps {
						if host.HostChange != "" {
							return host.HostChange
						}
						return common.RemovePortFromHost(r.Host)
					}
					return ""
				}(),
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				//logs.Debug("DialContext: start dialing; network=%s, addr=%s, using targetAddr=%s", network, addr, targetAddr)
				link := conn.NewLink("tcp", targetAddr, host.Client.Cnf.Crypt, host.Client.Cnf.Compress, r.RemoteAddr, s.allowLocalProxy && host.Target.LocalProxy)
				target, err := s.bridge.SendLinkInfo(host.Client.Id, link, nil)
				if err != nil {
					logs.Info("DialContext: connection to host %s (target %s) failed: %v", r.Host, targetAddr, err)
					return nil, err
				}
				rawConn := conn.GetConn(target, link.Crypt, link.Compress, host.Client.Rate, true)
				return conn.NewFlowConn(rawConn, host.Flow, host.Client.Flow), nil
			},
		},
		FlushInterval: 100 * time.Millisecond,
		ModifyResponse: func(resp *http.Response) error {
			// CORS
			if host.AutoCORS {
				origin := resp.Request.Header.Get("Origin")
				if origin != "" && resp.Header.Get("Access-Control-Allow-Origin") == "" {
					logs.Debug("ModifyResponse: setting CORS headers for origin=%s", origin)
					resp.Header.Set("Access-Control-Allow-Origin", origin)
					resp.Header.Set("Access-Control-Allow-Credentials", "true")
				}
			}
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			if err == io.EOF {
				logs.Info("ErrorHandler: io.EOF encountered, writing 521")
				rw.WriteHeader(521)
				return
			}
			logs.Warn("ErrorHandler: proxy error: method=%s, URL=%s, error=%v", req.Method, req.URL.String(), err)

			errMsg := err.Error()
			idx := strings.Index(errMsg, "Task")
			if idx == -1 {
				idx = strings.Index(errMsg, "Client")
			}
			if idx != -1 {
				http.Error(rw, errMsg[idx:], http.StatusTooManyRequests)
			} else {
				//http.Error(rw, "502 Bad Gateway", http.StatusBadGateway)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadGateway)
				w.Write(s.errorContent)
			}
		},
	}
	proxy.ServeHTTP(w, r)
}

func (s *httpServer) handleWebsocket(w http.ResponseWriter, r *http.Request, host *file.Host, targetAddr string, isHttpOnlyRequest bool) {
	logs.Info("%s websocket request, method %s, host %s, url %s, remote address %s, target %s", r.URL.Scheme, r.Method, r.Host, r.URL.Path, r.RemoteAddr, targetAddr)

	link := conn.NewLink("tcp", targetAddr, host.Client.Cnf.Crypt, host.Client.Cnf.Compress, r.RemoteAddr, host.Target.LocalProxy)
	targetConn, err := s.bridge.SendLinkInfo(host.Client.Id, link, nil)
	if err != nil {
		logs.Info("handleWebsocket: connection to target %s failed: %v", link.Host, err)
		//http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write(s.errorContent)
		return
	}
	rawConn := conn.GetConn(targetConn, link.Crypt, link.Compress, host.Client.Rate, true)
	wsConn := conn.NewRWConn(rawConn)
	var netConn net.Conn = wsConn

	if host.TargetIsHttps {
		serverName := host.HostChange
		if serverName == "" {
			serverName = common.RemovePortFromHost(r.Host)
		}
		//logs.Debug("handleWebsocket: performing TLS handshake, serverName=%s", serverName)
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		}
		netConn = tls.Client(netConn, tlsConf)
		if err := netConn.(*tls.Conn).Handshake(); err != nil {
			logs.Error("handleWebsocket: TLS handshake with backend failed: %v", err)
			//http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			w.Write(s.errorContent)
			return
		}
		//logs.Debug("handleWebsocket: TLS handshake succeeded")
	}

	common.ChangeHostAndHeader(r, host.HostChange, host.HeaderChange, isHttpOnlyRequest)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket hijacking not supported", http.StatusInternalServerError)
		logs.Error("handleWebsocket: WebSocket hijacking not supported.")
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "WebSocket hijacking failed", http.StatusInternalServerError)
		logs.Error("handleWebsocket: WebSocket hijacking failed.")
		return
	}
	//defer clientConn.Close()
	if err := r.Write(netConn); err != nil {
		logs.Error("handleWebsocket: failed to write handshake to backend: %v", err)
		netConn.Close()
		clientConn.Close()
		return
	}

	backendReader := bufio.NewReader(netConn)
	resp, err := http.ReadResponse(backendReader, r)
	if err != nil {
		logs.Error("handleWebsocket: failed to read handshake response from backend: %v", err)
		netConn.Close()
		clientConn.Close()
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		logs.Error("handleWebsocket: unexpected status code in handshake: %d", resp.StatusCode)
		netConn.Close()
		clientConn.Close()
		return
	}

	if err := resp.Write(clientBuf); err != nil {
		logs.Error("handleWebsocket: failed to write handshake response to client: %v", err)
		netConn.Close()
		clientConn.Close()
		return
	}
	if err := clientBuf.Flush(); err != nil {
		logs.Error("handleWebsocket: failed to flush handshake response to client: %v", err)
		netConn.Close()
		clientConn.Close()
		return
	}

	goroutine.Join(clientConn, netConn, []*file.Flow{host.Flow, host.Client.Flow}, s.task, r.RemoteAddr)
}

func (s *httpServer) NewServer(port int, scheme string) *http.Server {
	return &http.Server{
		Addr: ":" + strconv.Itoa(port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = scheme
			s.handleProxy(w, r)
		}),
		// Disable HTTP/2.
		//TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
}
