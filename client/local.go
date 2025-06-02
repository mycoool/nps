package client

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/config"
	"github.com/mycoool/nps/lib/conn"
	"github.com/mycoool/nps/lib/crypt"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/lib/nps_mux"
	"github.com/mycoool/nps/server/proxy"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/net/webdav"
)

// ------------------------------
// FileServerManager
// ------------------------------

type FileServerManager struct {
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	wg      sync.WaitGroup
	servers []struct {
		srv        *http.Server
		listener   *nps_mux.Mux
		remoteConn *conn.Conn
	}
}

func NewFileServerManager(parentCtx context.Context) *FileServerManager {
	ctx, cancel := context.WithCancel(parentCtx)
	fsm := &FileServerManager{
		ctx:    ctx,
		cancel: cancel,
	}
	go func() {
		<-parentCtx.Done()
		fsm.CloseAll()
	}()
	return fsm
}

func (fsm *FileServerManager) StartFileServer(cfg *config.CommonConfig, t *file.Tunnel, vkey string) {
	if fsm.ctx.Err() != nil {
		logs.Warn("file server manager already closed, skip StartFileServer")
		return
	}
	remoteConn, err := NewConn(cfg.Tp, vkey, cfg.Server, common.WORK_FILE, cfg.ProxyUrl)
	if err != nil {
		logs.Error("file server NewConn failed: %v", err)
		return
	}
	registered := false
	defer func() {
		if !registered {
			remoteConn.Close()
		}
	}()
	fs := http.FileServer(http.Dir(t.LocalPath))
	davHandler := &webdav.Handler{
		Prefix:     t.StripPre,
		FileSystem: webdav.Dir(t.LocalPath),
		LockSystem: webdav.NewMemLS(),
	}
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET", "HEAD":
			http.StripPrefix(t.StripPre, fs).ServeHTTP(w, r)
		default:
			davHandler.ServeHTTP(w, r)
		}
	})
	accounts := make(map[string]string)
	if t.Client != nil && t.Client.Cnf != nil && t.Client.Cnf.U != "" && t.Client.Cnf.P != "" {
		accounts[t.Client.Cnf.U] = t.Client.Cnf.P
	}
	if t.MultiAccount != nil {
		for user, pass := range t.MultiAccount.AccountMap {
			accounts[user] = pass
		}
	}
	if t.UserAuth != nil {
		for user, pass := range t.UserAuth.AccountMap {
			accounts[user] = pass
		}
	}
	//logs.Error("%v", accounts)
	if len(accounts) > 0 {
		handler = basicAuth(accounts, "WebDAV", handler)
	}
	srv := &http.Server{
		BaseContext: func(_ net.Listener) context.Context { return fsm.ctx },
		Handler:     handler,
	}
	logs.Info("start WebDAV server, local path %s, strip prefix %s, remote port %s", t.LocalPath, t.StripPre, t.Ports)
	listener := nps_mux.NewMux(remoteConn.Conn, common.CONN_TCP, cfg.DisconnectTime)
	fsm.mu.Lock()
	fsm.servers = append(fsm.servers, struct {
		srv        *http.Server
		listener   *nps_mux.Mux
		remoteConn *conn.Conn
	}{srv, listener, remoteConn})
	fsm.mu.Unlock()
	registered = true

	fsm.wg.Add(1)
	go func() {
		defer fsm.wg.Done()
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			logs.Error("WebDAV Serve error: %v", err)
		}
	}()
}

func (fsm *FileServerManager) CloseAll() {
	fsm.cancel()
	fsm.mu.Lock()
	entries := fsm.servers
	fsm.servers = nil
	fsm.mu.Unlock()
	for _, e := range entries {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		if err := e.srv.Shutdown(ctx2); err != nil {
			logs.Error("FileServer Shutdown error: %v", err)
		}
		cancel2()
		e.listener.Close()
		e.remoteConn.Close()
	}
	fsm.wg.Wait()
}

func basicAuth(users map[string]string, realm string, next http.Handler) http.Handler {
	if len(users) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		payload, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(string(payload), ":", 2)
		if len(parts) != 2 || users[parts[0]] != parts[1] {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ------------------------------
// P2PManager
// ------------------------------

type Closer interface{ Close() error }

type P2PManager struct {
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	wg           sync.WaitGroup
	tcpLn        []*net.TCPListener
	udpConn      net.Conn
	muxSession   *nps_mux.Mux
	bridge       *p2pBridge
	statusOK     bool
	proxyServers []Closer
}

type p2pBridge struct{ mgr *P2PManager }

func NewP2PManager(parentCtx context.Context) *P2PManager {
	ctx, cancel := context.WithCancel(parentCtx)
	mgr := &P2PManager{
		ctx:          ctx,
		cancel:       cancel,
		proxyServers: make([]Closer, 0),
	}
	mgr.bridge = &p2pBridge{mgr: mgr}
	go func() {
		<-parentCtx.Done()
		mgr.Close()
	}()
	return mgr
}

func (b *p2pBridge) SendLinkInfo(clientId int, link *conn.Link, t *file.Tunnel) (net.Conn, error) {
	mgr := b.mgr
	ctx, cancel := context.WithTimeout(mgr.ctx, 200*time.Millisecond)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			mgr.mu.Lock()
			mgr.statusOK = false
			mgr.mu.Unlock()
			return nil, errors.New("timeout waiting muxSession")
		case <-ticker.C:
			mgr.mu.Lock()
			session := mgr.muxSession
			mgr.mu.Unlock()
			if session == nil || session.IsClose {
				continue
			}
			nowConn, err := session.NewConn()
			if err != nil {
				mgr.mu.Lock()
				mgr.statusOK = false
				mgr.mu.Unlock()
				return nil, err
			}
			if _, err := conn.NewConn(nowConn).SendInfo(link, ""); err != nil {
				nowConn.Close()
				mgr.mu.Lock()
				mgr.statusOK = false
				mgr.mu.Unlock()
				return nil, err
			}
			mgr.mu.Lock()
			mgr.statusOK = true
			mgr.mu.Unlock()
			return nowConn, nil
		}
	}
}

func (mgr *P2PManager) StartLocalServer(l *config.LocalServer, cfg *config.CommonConfig) error {
	if mgr.ctx.Err() != nil {
		return errors.New("parent context canceled")
	}
	if l.Type != "secret" {
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			mgr.handleUdpMonitor(cfg, l)
		}()
	}
	task := &file.Tunnel{
		Port:     l.Port,
		ServerIp: "0.0.0.0",
		Status:   true,
		Client: &file.Client{
			Cnf: &file.Config{
				U:        "",
				P:        "",
				Compress: cfg.Client.Cnf.Compress,
			},
			Status:    true,
			RateLimit: 0,
			Flow:      &file.Flow{},
		},
		HttpProxy:   true,
		Socks5Proxy: true,
		Flow:        &file.Flow{},
		Target:      &file.Target{},
	}
	switch l.Type {
	case "p2ps":
		logs.Info("start http/socks5 monitor port %d", l.Port)
		srv := proxy.NewTunnelModeServer(proxy.ProcessMix, mgr.bridge, task)
		mgr.mu.Lock()
		mgr.proxyServers = append(mgr.proxyServers, srv)
		mgr.mu.Unlock()
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			srv.Start()
		}()
		return nil
	case "p2pt":
		logs.Info("start tcp trans monitor port %d", l.Port)
		srv := proxy.NewTunnelModeServer(proxy.HandleTrans, mgr.bridge, task)
		mgr.mu.Lock()
		mgr.proxyServers = append(mgr.proxyServers, srv)
		mgr.mu.Unlock()
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			srv.Start()
		}()
		return nil
	}

	listenTCP, errTCP := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: l.Port})
	if errTCP != nil {
		logs.Error("local tcp monitoring startup failed port %d, error %v", l.Port, errTCP)
		return errTCP
	}
	mgr.mu.Lock()
	mgr.tcpLn = append(mgr.tcpLn, listenTCP)
	mgr.mu.Unlock()

	logs.Info("local tcp monitoring started on port %d", l.Port)
	if l.Type == "p2p" {
		task.Target.TargetStr = l.Target
		logs.Info("local udp monitoring started on port %d", l.Port)
		srv := proxy.NewUdpModeServer(mgr.bridge, task)
		mgr.mu.Lock()
		mgr.proxyServers = append(mgr.proxyServers, srv)
		mgr.mu.Unlock()

		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			srv.Start()
		}()
	}

	mgr.wg.Add(1)
	go func() {
		defer mgr.wg.Done()
		conn.Accept(listenTCP, func(c net.Conn) {
			logs.Trace("new %s connection, remote address %s", l.Type, c.RemoteAddr().String())
			if l.Type == "secret" {
				mgr.handleSecret(c, cfg, l)
			} else if l.Type == "p2p" {
				mgr.handleP2PVisitor(c, cfg, l)
			}
		})
	}()

	return nil
}

func (mgr *P2PManager) handleUdpMonitor(cfg *config.CommonConfig, l *config.LocalServer) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mgr.ctx.Done():
			return
		case <-ticker.C:
		}
		mgr.mu.Lock()
		ok := mgr.statusOK && mgr.udpConn != nil
		oldConn := mgr.udpConn
		mgr.mu.Unlock()

		if ok {
			continue
		}

		mgr.mu.Lock()
		if oldConn != nil {
			oldConn.Close()
			mgr.udpConn = nil
		}
		mgr.mu.Unlock()

		tmpConnV4, errV4 := common.GetLocalUdp4Addr()
		if errV4 != nil {
			logs.Warn("Failed to get local IPv4 address: %v", errV4)
		} else {
			logs.Debug("IPv4 address: %v", tmpConnV4.LocalAddr())
		}

		tmpConnV6, errV6 := common.GetLocalUdp6Addr()
		if errV6 != nil {
			logs.Warn("Failed to get local IPv6 address: %v", errV6)
		} else {
			logs.Debug("IPv6 address: %v", tmpConnV6.LocalAddr())
		}

		if errV4 != nil && errV6 != nil {
			logs.Error("Both IPv4 and IPv6 address retrieval failed, exiting.")
			mgr.mu.Lock()
			mgr.statusOK = false
			mgr.mu.Unlock()
			return
		}

		for i := 0; i < 10; i++ {
			logs.Debug("try P2P hole punch %d", i+1)
			select {
			case <-mgr.ctx.Done():
				return
			default:
			}
			if errV4 == nil {
				mgr.newUdpConn(tmpConnV4.LocalAddr().String(), cfg, l)
			}
			mgr.mu.Lock()
			if mgr.statusOK {
				mgr.mu.Unlock()
				break
			}
			mgr.mu.Unlock()
			if errV6 == nil {
				mgr.newUdpConn(tmpConnV6.LocalAddr().String(), cfg, l)
			}
			mgr.mu.Lock()
			if mgr.statusOK {
				mgr.mu.Unlock()
				break
			}
			mgr.mu.Unlock()
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func (mgr *P2PManager) newUdpConn(localAddr string, cfg *config.CommonConfig, l *config.LocalServer) {
	remoteConn, err := NewConn(cfg.Tp, cfg.VKey, cfg.Server, common.WORK_P2P, cfg.ProxyUrl)
	if err != nil {
		logs.Error("newUdpConn NewConn failed: %v", err)
		return
	}
	defer remoteConn.Close()
	if _, err := remoteConn.Write([]byte(crypt.Md5(l.Password))); err != nil {
		logs.Error("newUdpConn write pwd failed: %v", err)
		return
	}
	rAddrBuf, err := remoteConn.GetShortLenContent()
	if err != nil {
		logs.Error("newUdpConn GetShortLenContent: %v", err)
		return
	}
	rAddr := string(rAddrBuf)
	remoteIP := net.ParseIP(common.GetIpByAddr(remoteConn.RemoteAddr().String()))
	if remoteIP != nil && (remoteIP.IsPrivate() || remoteIP.IsLoopback() || remoteIP.IsLinkLocalUnicast()) {
		rAddr = common.BuildAddress(remoteIP.String(), strconv.Itoa(common.GetPortByAddr(rAddr)))
	}

	if !common.IsSameIPType(localAddr, rAddr) {
		logs.Debug("IP type mismatch local=%s remote=%s", localAddr, rAddr)
		return
	}
	//logs.Debug("localAddr is %s, rAddr is %s", localAddr, rAddr)

	remoteAddr, localConn, err := handleP2PUdp(mgr.ctx, localAddr, rAddr, crypt.Md5(l.Password), common.WORK_P2P_VISITOR)
	if err != nil {
		logs.Error("handleP2PUdp failed: %v", err)
		return
	}

	udpTunnel, err := kcp.NewConn(remoteAddr, nil, 150, 3, localConn)
	if err != nil || udpTunnel == nil {
		logs.Warn("kcp NewConn failed: %v", err)
		localConn.Close()
		return
	}
	conn.SetUdpSession(udpTunnel)
	logs.Info("P2P UDP tunnel established to %s", remoteAddr)

	mgr.mu.Lock()
	if mgr.udpConn != nil {
		mgr.udpConn.Close()
	}
	if mgr.muxSession != nil {
		mgr.muxSession.Close()
	}
	mgr.udpConn = udpTunnel
	mgr.muxSession = nps_mux.NewMux(udpTunnel, "kcp", cfg.DisconnectTime)
	mgr.statusOK = true
	mgr.mu.Unlock()
}

func (mgr *P2PManager) handleSecret(c net.Conn, cfg *config.CommonConfig, l *config.LocalServer) {
	remoteConn, err := NewConn(cfg.Tp, cfg.VKey, cfg.Server, common.WORK_SECRET, cfg.ProxyUrl)
	if err != nil {
		logs.Error("secret NewConn failed: %v", err)
		c.Close()
		return
	}
	defer remoteConn.Close()
	if _, err := remoteConn.Write([]byte(crypt.Md5(l.Password))); err != nil {
		logs.Error("secret write failed: %v", err)
		c.Close()
		return
	}
	conn.CopyWaitGroup(remoteConn.Conn, c, false, false, nil, nil, false, 0, nil, nil)
}

func (mgr *P2PManager) handleP2PVisitor(c net.Conn, cfg *config.CommonConfig, l *config.LocalServer) {
	mgr.mu.Lock()
	tunnel := mgr.udpConn
	ok := mgr.statusOK
	mgr.mu.Unlock()

	if tunnel == nil || !ok {
		logs.Warn("P2P not ready, fallback to secret")
		mgr.handleSecret(c, cfg, l)
		return
	}
	logs.Trace("using P2P for connection")
	//TODO just support compress now because there is not tls file in client packages
	link := conn.NewLink(common.CONN_TCP, l.Target, false, cfg.Client.Cnf.Compress, c.LocalAddr().String(), false)
	target, err := mgr.bridge.SendLinkInfo(0, link, nil)
	if err != nil {
		logs.Error("SendLinkInfo failed: %v", err)
		mgr.mu.Lock()
		mgr.statusOK = false
		mgr.mu.Unlock()
		c.Close()
		return
	}
	defer target.Close()
	conn.CopyWaitGroup(target, c, false, cfg.Client.Cnf.Compress, nil, nil, false, 0, nil, nil)
}

func (mgr *P2PManager) Close() {
	mgr.cancel()
	mgr.mu.Lock()
	lnList := mgr.tcpLn
	psList := mgr.proxyServers
	udp := mgr.udpConn
	mux := mgr.muxSession
	mgr.mu.Unlock()

	for _, ln := range lnList {
		ln.Close()
	}
	for _, srv := range psList {
		srv.Close()
	}
	if udp != nil {
		udp.Close()
	}
	if mux != nil {
		mux.Close()
	}
	mgr.wg.Wait()
}
