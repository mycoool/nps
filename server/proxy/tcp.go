package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/beego/beego"
	"github.com/mycoool/nps/bridge"
	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/conn"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/server/connection"
)

var _ = unsafe.Sizeof(0)

//var httpNum = 0

//go:linkname initBeforeHTTPRun github.com/beego/beego.initBeforeHTTPRun
func initBeforeHTTPRun()

type TunnelModeServer struct {
	BaseServer
	process           process
	listener          net.Listener
	activeConnections sync.Map
}

// tcp|host|mixproxy
func NewTunnelModeServer(process process, bridge NetBridge, task *file.Tunnel) *TunnelModeServer {
	allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy")
	s := new(TunnelModeServer)
	s.bridge = bridge
	s.process = process
	s.task = task
	s.allowLocalProxy = allowLocalProxy
	s.activeConnections = sync.Map{} // 初始化连接池
	return s
}

func (s *TunnelModeServer) Start() error {
	return conn.NewTcpListenerAndProcess(common.BuildAddress(s.task.ServerIp, strconv.Itoa(s.task.Port)), func(c net.Conn) {
		s.activeConnections.Store(c, struct{}{})
		defer func() {
			s.activeConnections.Delete(c)
			if c != nil {
				c.Close()
			}
		}()

		if err := s.CheckFlowAndConnNum(s.task.Client); err != nil {
			logs.Warn("client id %d, task id %d, error %v, when tcp connection", s.task.Client.Id, s.task.Id, err)
			c.Close()
			return
		}

		logs.Trace("new tcp connection,local port %d,client %d,remote address %v", s.task.Port, s.task.Client.Id, c.RemoteAddr())

		s.process(conn.NewConn(c), s)
		s.task.Client.CutConn()
	}, &s.listener)
}

func (s *TunnelModeServer) Close() error {
	s.activeConnections.Range(func(key, value interface{}) bool {
		if c, ok := key.(net.Conn); ok {
			c.Close()
			s.activeConnections.Delete(key)
		}
		return true
	})
	s.activeConnections = sync.Map{}
	return s.listener.Close()
}

type WebServer struct {
	BaseServer
}

func (s *WebServer) Start() error {
	p, _ := beego.AppConfig.Int("web_port")
	if p == 0 {
		stop := make(chan struct{})
		<-stop
	}
	beego.BConfig.WebConfig.Session.SessionOn = true
	beego.SetStaticPath(beego.AppConfig.String("web_base_url")+"/static", filepath.Join(common.GetRunPath(), "web", "static"))
	beego.SetViewsPath(filepath.Join(common.GetRunPath(), "web", "views"))
	err := errors.New("Web management startup failure ")
	var l net.Listener
	if l, err = connection.GetWebManagerListener(); err == nil {
		initBeforeHTTPRun()
		if beego.AppConfig.String("web_open_ssl") == "true" {
			keyPath := beego.AppConfig.String("web_key_file")
			certPath := beego.AppConfig.String("web_cert_file")
			err = http.ServeTLS(l, beego.BeeApp.Handlers, certPath, keyPath)
		} else {
			err = http.Serve(l, beego.BeeApp.Handlers)
		}
	} else {
		logs.Error("%v", err)
	}
	return err
}

func (s *WebServer) Close() error {
	return nil
}

// new
func NewWebServer(bridge *bridge.Bridge) *WebServer {
	s := new(WebServer)
	s.bridge = bridge
	return s
}

type process func(c *conn.Conn, s *TunnelModeServer) error

// tcp proxy
func ProcessTunnel(c *conn.Conn, s *TunnelModeServer) error {
	targetAddr, err := s.task.Target.GetRandomTarget()
	if err != nil {
		if s.task.Mode != "file" {
			c.Close()
			logs.Warn("tcp port %d, client id %d, task id %d connect error %v", s.task.Port, s.task.Client.Id, s.task.Id, err)
			return err
		}
		targetAddr = ""
	}

	return s.DealClient(c, s.task.Client, targetAddr, nil, common.CONN_TCP, nil, []*file.Flow{s.task.Flow, s.task.Client.Flow}, s.task.Target.ProxyProtocol, s.task.Target.LocalProxy, s.task)
}

// http proxy
func ProcessHttp(c *conn.Conn, s *TunnelModeServer) error {
	_, addr, rb, err, r := c.GetHost()
	if err != nil {
		c.Close()
		logs.Info("%v", err)
		return err
	}
	if err := s.auth(r, nil, s.task.Client.Cnf.U, s.task.Client.Cnf.P, s.task.MultiAccount, s.task.UserAuth); err != nil {
		c.Write([]byte(common.ProxyAuthRequiredBytes))
		c.Close()
		return err
	}
	remoteAddr := c.Conn.RemoteAddr().String()
	logs.Debug("http proxy request, client=%d method=%s, host=%s, url=%s, remote address=%s, target=%s", s.task.Client.Id, r.Method, r.Host, r.URL.RequestURI(), remoteAddr, addr)
	if r.Method == http.MethodConnect {
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		return s.DealClient(c, s.task.Client, addr, nil, common.CONN_TCP, nil, []*file.Flow{s.task.Flow, s.task.Client.Flow}, s.task.Target.ProxyProtocol, s.task.Target.LocalProxy, s.task)
	}
	var server *http.Server

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			//req.RequestURI = ""
			//req.Header.Del("Proxy-Connection")
			//req.Header.Del("Proxy-Authenticate")
			//req.Header.Del("Proxy-Authorization")
			//req.Header.Del("TE")
			//req.Header.Del("Trailers")
			//req.Header.Del("Transfer-Encoding")
			//req.Header.Del("Upgrade")
			//connections := req.Header.Get("Connection")
			//req.Header.Del("Connection")
			//if connections != "" {
			//	for _, h := range strings.Split(connections, ",") {
			//		req.Header.Del(strings.TrimSpace(h))
			//	}
			//}
			req.Header["X-Forwarded-For"] = nil
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: 60 * time.Second,
			//DisableKeepAlives:     true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				link := conn.NewLink("tcp", addr, s.task.Client.Cnf.Crypt, s.task.Client.Cnf.Compress, remoteAddr, s.task.Target.LocalProxy)
				target, err := s.bridge.SendLinkInfo(s.task.Client.Id, link, nil)
				if err != nil {
					logs.Trace("DialContext: connection to host %s (target %s) failed: %v", r.Host, addr, err)
					return nil, err
				}
				rawConn := conn.GetConn(target, link.Crypt, link.Compress, s.task.Client.Rate, true)
				return conn.NewFlowConn(rawConn, s.task.Flow, s.task.Client.Flow), nil
			},
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			if err == io.EOF {
				//logs.Info("ErrorHandler: io.EOF encountered, writing 521")
				rw.WriteHeader(521)
				//go server.Close()
				return
			}
			logs.Debug("ErrorHandler: proxy error: method=%s, URL=%s, error=%v", req.Method, req.URL.String(), err)
			errMsg := err.Error()
			idx := strings.Index(errMsg, "Task")
			if idx == -1 {
				idx = strings.Index(errMsg, "Client")
			}
			if idx != -1 {
				http.Error(rw, errMsg[idx:], http.StatusTooManyRequests)
			} else {
				rw.WriteHeader(http.StatusBadGateway)
			}
			//go server.Close()
		},
	}
	var listener *conn.OneConnListener
	if c.Rb == nil {
		c.Rb = rb
		listener = conn.NewOneConnListener(c)
	} else {
		cc := conn.NewConn(c)
		cc.Rb = rb
		listener = conn.NewOneConnListener(cc)
	}
	var shutdownTimerMu sync.Mutex
	var shutdownTimer *time.Timer
	defer func() {
		listener.Close()
		shutdownTimerMu.Lock()
		if shutdownTimer != nil {
			shutdownTimer.Stop()
		}
		shutdownTimerMu.Unlock()
	}()
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		shutdownTimerMu.Lock()
		if shutdownTimer != nil {
			shutdownTimer.Stop()
		}
		shutdownTimerMu.Unlock()
		defer func() {
			//logs.Error("HTTP Proxy Number: %d, Reset timeout", httpNum)
			shutdownTimerMu.Lock()
			shutdownTimer = time.AfterFunc(30*time.Second, func() {
				server.Close()
			})
			shutdownTimerMu.Unlock()
		}()
		proxy.ServeHTTP(w, req)
	})
	server = &http.Server{
		Handler: handler,
	}
	//httpNum++
	//logs.Error("HTTP Proxy Number: %d", httpNum)
	//defer func() {
	//	httpNum--
	//	logs.Error("HTTP Proxy Number: %d", httpNum)
	//}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	//logs.Error("HTTP Proxy Close")
	return nil
}
