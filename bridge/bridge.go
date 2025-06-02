package bridge

import (
	"bytes"
	"crypto/tls"
	_ "crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego"
	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/conn"
	"github.com/mycoool/nps/lib/crypt"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/lib/nps_mux"
	"github.com/mycoool/nps/lib/version"
	"github.com/mycoool/nps/server/connection"
	"github.com/mycoool/nps/server/tool"
)

var (
	ServerTcpEnable  bool = false
	ServerKcpEnable  bool = false
	ServerTlsEnable  bool = false
	ServerWsEnable   bool = false
	ServerWssEnable  bool = false
	ServerSecureMode bool = false
)

type replay struct {
	mu    sync.Mutex
	items map[string]int64
	ttl   int64
}

var rep = replay{
	items: make(map[string]int64, 100),
	ttl:   300,
}

func IsReplay(key string) bool {
	now := time.Now().Unix()
	rep.mu.Lock()
	defer rep.mu.Unlock()
	expireBefore := now - rep.ttl
	for k, ts := range rep.items {
		if ts < expireBefore {
			delete(rep.items, k)
		}
	}
	if _, ok := rep.items[key]; ok {
		return true
	}
	rep.items[key] = now
	return false
}

type Client struct {
	signal    *conn.Conn   // WORK_MAIN connection
	tunnel    *nps_mux.Mux // WORK_CHAN connection
	file      *nps_mux.Mux // WORK_FILE connection
	Version   string
	retryTime int      // it will add 1 when ping not ok until to 3 will close the client
	signals   sync.Map // map[*conn.Conn]struct{}
	tunnels   sync.Map // map[*nps_mux.Mux]struct{}
}

func NewClient(t, f *nps_mux.Mux, s *conn.Conn, vs string) *Client {
	cli := &Client{
		signal:  s,
		tunnel:  t,
		file:    f,
		Version: vs,
		signals: sync.Map{},
		tunnels: sync.Map{},
	}
	return cli
}

type Bridge struct {
	TunnelPort     int
	Client         *sync.Map
	Register       *sync.Map
	tunnelType     string //bridge type kcp or tcp
	OpenTask       chan *file.Tunnel
	CloseTask      chan *file.Tunnel
	CloseClient    chan int
	SecretChan     chan *conn.Secret
	ipVerify       bool
	runList        *sync.Map //map[int]interface{}
	disconnectTime int
}

func NewTunnel(tunnelPort int, tunnelType string, ipVerify bool, runList *sync.Map, disconnectTime int) *Bridge {
	return &Bridge{
		TunnelPort:     tunnelPort,
		tunnelType:     tunnelType,
		Client:         &sync.Map{},
		Register:       &sync.Map{},
		OpenTask:       make(chan *file.Tunnel, 100),
		CloseTask:      make(chan *file.Tunnel, 100),
		CloseClient:    make(chan int, 100),
		SecretChan:     make(chan *conn.Secret, 100),
		ipVerify:       ipVerify,
		runList:        runList,
		disconnectTime: disconnectTime,
	}
}

func (s *Bridge) StartTunnel() error {
	go s.ping()
	if s.tunnelType == "kcp" {
		logs.Info("server start, the bridge type is %s, the bridge port is %d", s.tunnelType, s.TunnelPort)
		return conn.NewKcpListenerAndProcess(common.BuildAddress(beego.AppConfig.String("bridge_ip"), beego.AppConfig.String("bridge_port")), func(c net.Conn) {
			s.cliProcess(conn.NewConn(c), "kcp")
		})
	} else {
		// tcp
		if ServerTcpEnable {
			go func() {
				listener, err := connection.GetBridgeTcpListener()
				if err != nil {
					logs.Error("%v", err)
					os.Exit(0)
					return
				}
				conn.Accept(listener, func(c net.Conn) {
					s.cliProcess(conn.NewConn(c), "tcp")
				})
			}()
		}

		// tls
		if ServerTlsEnable {
			go func() {
				tlsListener, tlsErr := connection.GetBridgeTlsListener()
				if tlsErr != nil {
					logs.Error("%v", tlsErr)
					os.Exit(0)
					return
				}
				conn.Accept(tlsListener, func(c net.Conn) {
					s.cliProcess(conn.NewConn(tls.Server(c, &tls.Config{Certificates: []tls.Certificate{crypt.GetCert()}})), "tls")
				})
			}()
		}

		// ws
		if ServerWsEnable {
			go func() {
				wsListener, wsErr := connection.GetBridgeWsListener()
				if wsErr != nil {
					logs.Error("%v", wsErr)
					os.Exit(0)
					return
				}
				wsLn := conn.NewWSListener(wsListener, beego.AppConfig.String("bridge_path"))
				conn.Accept(wsLn, func(c net.Conn) {
					s.cliProcess(conn.NewConn(c), "ws")
				})
			}()
		}

		// wss
		if ServerWssEnable {
			go func() {
				wssListener, wssErr := connection.GetBridgeWssListener()
				if wssErr != nil {
					logs.Error("%v", wssErr)
					os.Exit(0)
					return
				}
				wssLn := conn.NewWSSListener(wssListener, beego.AppConfig.String("bridge_path"), crypt.GetCert())
				conn.Accept(wssLn, func(c net.Conn) {
					s.cliProcess(conn.NewConn(c), "wss")
				})
			}()
		}

		// kcp
		if ServerKcpEnable {
			kcpIp := beego.AppConfig.DefaultString("bridge_kcp_ip", beego.AppConfig.String("bridge_ip"))
			kcpPort := beego.AppConfig.DefaultString("bridge_kcp_port", beego.AppConfig.String("bridge_port"))
			logs.Info("server start, the bridge type is kcp, the bridge port is %s", kcpPort)
			go func() {
				bridgeKcp := *s
				bridgeKcp.tunnelType = "kcp"
				conn.NewKcpListenerAndProcess(common.BuildAddress(kcpIp, kcpPort), func(c net.Conn) {
					bridgeKcp.cliProcess(conn.NewConn(c), "kcp")
				})
			}()
		}
	}
	return nil
}

// get health information form client
func (s *Bridge) GetHealthFromClient(id int, c *conn.Conn) {
	if id <= 0 {
		return
	}

	for {
		if info, status, err := c.GetHealthInfo(); err != nil {
			break
		} else if !status { //the status is true , return target to the targetArr
			file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
				v := value.(*file.Tunnel)
				if v.Client.Id == id && v.Mode == "tcp" && strings.Contains(v.Target.TargetStr, info) {
					v.Lock()
					if v.Target.TargetArr == nil || (len(v.Target.TargetArr) == 0 && len(v.HealthRemoveArr) == 0) {
						v.Target.TargetArr = common.TrimArr(strings.Split(strings.ReplaceAll(v.Target.TargetStr, "\r\n", "\n"), "\n"))
					}
					v.Target.TargetArr = common.RemoveArrVal(v.Target.TargetArr, info)
					if v.HealthRemoveArr == nil {
						v.HealthRemoveArr = make([]string, 0)
					}
					v.HealthRemoveArr = append(v.HealthRemoveArr, info)
					v.Unlock()
				}
				return true
			})
			file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
				v := value.(*file.Host)
				if v.Client.Id == id && strings.Contains(v.Target.TargetStr, info) {
					v.Lock()
					if v.Target.TargetArr == nil || (len(v.Target.TargetArr) == 0 && len(v.HealthRemoveArr) == 0) {
						v.Target.TargetArr = common.TrimArr(strings.Split(strings.ReplaceAll(v.Target.TargetStr, "\r\n", "\n"), "\n"))
					}
					v.Target.TargetArr = common.RemoveArrVal(v.Target.TargetArr, info)
					if v.HealthRemoveArr == nil {
						v.HealthRemoveArr = make([]string, 0)
					}
					v.HealthRemoveArr = append(v.HealthRemoveArr, info)
					v.Unlock()
				}
				return true
			})
		} else { //the status is false,remove target from the targetArr
			file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
				v := value.(*file.Tunnel)
				if v.Client.Id == id && v.Mode == "tcp" && common.IsArrContains(v.HealthRemoveArr, info) && !common.IsArrContains(v.Target.TargetArr, info) {
					v.Lock()
					v.Target.TargetArr = append(v.Target.TargetArr, info)
					v.HealthRemoveArr = common.RemoveArrVal(v.HealthRemoveArr, info)
					v.Unlock()
				}
				return true
			})

			file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
				v := value.(*file.Host)
				if v.Client.Id == id && common.IsArrContains(v.HealthRemoveArr, info) && !common.IsArrContains(v.Target.TargetArr, info) {
					v.Lock()
					v.Target.TargetArr = append(v.Target.TargetArr, info)
					v.HealthRemoveArr = common.RemoveArrVal(v.HealthRemoveArr, info)
					v.Unlock()
				}
				return true
			})
		}
	}
	s.DelClient(id)
}

func (s *Bridge) verifyError(c *conn.Conn) {
	if !ServerSecureMode {
		c.Write([]byte(common.VERIFY_EER))
	}
	c.Close()
}

func (s *Bridge) verifySuccess(c *conn.Conn) {
	c.Write([]byte(common.VERIFY_SUCCESS))
}

func (s *Bridge) cliProcess(c *conn.Conn, tunnelType string) {
	if c.Conn == nil || c.Conn.RemoteAddr() == nil {
		logs.Warn("Invalid connection")
		c.Close()
		return
	}

	//read test flag
	if _, err := c.GetShortContent(3); err != nil {
		logs.Trace("The client %v connect error: %v", c.Conn.RemoteAddr(), err)
		c.Close()
		return
	}
	//version check
	ver := version.GetLatestIndex()
	minVerBytes, err := c.GetShortLenContent()
	if err != nil {
		logs.Error("Failed to read version length from client %v: %v", c.Conn.RemoteAddr(), err)
		c.Close()
		return
	}
	if !ServerSecureMode {
		ver = version.GetIndex(string(minVerBytes))
	}
	if string(minVerBytes) != version.GetVersion(ver) {
		logs.Warn("Client %v basic version mismatch: expected %s, got %s", c.Conn.RemoteAddr(), version.GetVersion(ver), string(minVerBytes))
		c.Close()
		return
	}

	//version get
	vs, err := c.GetShortLenContent()
	if err != nil {
		logs.Error("Failed to read client version from %v: %v", c.Conn.RemoteAddr(), err)
		c.Close()
		return
	}
	clientVer := string(vs)

	if ver == 0 {
		// --- protocol 0.26.0 path ---
		//write server version to client
		if _, err := c.Write([]byte(crypt.Md5(version.GetVersion(ver)))); err != nil {
			logs.Error("Failed to write server version to client %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		c.SetReadDeadlineBySecond(5)
		//get vKey from client
		keyBuf, err := c.GetShortContent(32)
		if err != nil {
			logs.Error("Failed to read vKey from client %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		//verify
		id, err := file.GetDb().GetIdByVerifyKey(string(keyBuf), c.Conn.RemoteAddr().String(), "", crypt.Md5)
		if err != nil {
			logs.Error("Validation error for client %v (proto-ver %d, vKey %x): %v", c.Conn.RemoteAddr(), ver, keyBuf, err)
			s.verifyError(c)
			return
		}
		s.verifySuccess(c)

		flag, err := c.ReadFlag()
		if err != nil {
			logs.Warn("Failed to read operation flag from %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		s.typeDeal(flag, c, id, clientVer)
	} else {
		// --- protocol 0.27.0+ path ---
		tsBuf, err := c.GetShortContent(8)
		if err != nil {
			logs.Error("Failed to read timestamp from client %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		ts := common.BytesToTimestamp(tsBuf)
		now := time.Now().Unix()
		if ServerSecureMode && (ts > now+rep.ttl || ts < now-rep.ttl) {
			logs.Error("Timestamp validation failed for %v: ts=%d, now=%d", c.Conn.RemoteAddr(), ts, now)
			c.Close()
			return
		}
		keyBuf, err := c.GetShortContent(64)
		if err != nil {
			logs.Error("Failed to read vKey (64 bytes) from %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		//verify
		//id, err := file.GetDb().GetIdByVerifyKey(string(keyBuf), c.Conn.RemoteAddr().String(), "", crypt.Blake2b)
		id, err := file.GetDb().GetClientIdByBlake2bVkey(string(keyBuf))
		if err != nil {
			logs.Error("Validation error for client %v (proto-ver %d, vKey %x): %v", c.Conn.RemoteAddr(), ver, keyBuf, err)
			s.verifyError(c)
			return
		}
		client, err := file.GetDb().GetClient(id)
		if err != nil {
			logs.Error("Failed to load client record for ID %d: %v", id, err)
			c.Close()
			return
		}
		client.Addr = common.GetIpByAddr(c.Conn.RemoteAddr().String())
		infoBuf, err := c.GetShortLenContent()
		if err != nil {
			logs.Error("Failed to read encrypted IP from %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		infoDec, err := crypt.DecryptBytes(infoBuf, client.VerifyKey)
		if err != nil {
			logs.Error("Failed to decrypt Info for %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		if ver < 3 {
			// --- protocol 0.27.0 - 0.28.0 path ---
			client.LocalAddr = common.DecodeIP(infoDec).String()
			client.Mode = tunnelType
		} else {
			// --- protocol 0.29.0+ path ---
			// infoDec = [17-byte IP][1-byte L][L-byte tp]
			if len(infoDec) < 18 {
				logs.Error("Invalid payload length from %v: %d", c.Conn.RemoteAddr(), len(infoDec))
				c.Close()
				return
			}
			ipPart := infoDec[:17]
			l := int(infoDec[17])
			if len(infoDec) < 18+l {
				logs.Error("Declared tp length %d exceeds payload from %v", l, c.Conn.RemoteAddr())
				c.Close()
				return
			}
			ip := common.DecodeIP(ipPart)
			if ip == nil {
				logs.Error("Failed to decode IP from %v", c.Conn.RemoteAddr())
				c.Close()
				return
			}
			client.LocalAddr = ip.String()
			tp := string(infoDec[18 : 18+l])
			client.Mode = fmt.Sprintf("%s,%s", tunnelType, tp)
		}
		randBuf, err := c.GetShortLenContent()
		if err != nil {
			logs.Error("Failed to read random buffer from %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		hmacBuf, err := c.GetShortContent(32)
		if err != nil {
			logs.Error("Failed to read HMAC from %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		if ServerSecureMode && !bytes.Equal(hmacBuf, crypt.ComputeHMAC(client.VerifyKey, ts, minVerBytes, vs, infoBuf, randBuf)) {
			logs.Error("HMAC verification failed for %v", c.Conn.RemoteAddr())
			c.Close()
			return
		}
		if ServerSecureMode && IsReplay(string(hmacBuf)) {
			logs.Error("Replay detected for client %v", c.Conn.RemoteAddr())
			c.Close()
			return
		}
		if _, err := c.Write(crypt.ComputeHMAC(client.VerifyKey, ts, hmacBuf, []byte(version.GetVersion(ver)))); err != nil {
			logs.Error("Failed to write HMAC response to %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		if ver > 1 {
			// --- protocol 0.28.0+ path ---
			fpBuf, err := crypt.EncryptBytes(crypt.GetCertFingerprint(crypt.GetCert()), client.VerifyKey)
			if err != nil {
				logs.Error("Failed to encrypt cert fingerprint for %v: %v", c.Conn.RemoteAddr(), err)
				c.Close()
				return
			}
			c.WriteLenContent(fpBuf)
		}
		c.SetReadDeadlineBySecond(5)

		flag, err := c.ReadFlag()
		if err != nil {
			logs.Warn("Failed to read operation flag from %v: %v", c.Conn.RemoteAddr(), err)
			c.Close()
			return
		}
		s.typeDeal(flag, c, id, clientVer)
	}
	return
}

func (s *Bridge) DelClient(id int) {
	if v, ok := s.Client.Load(id); ok {
		client := v.(*Client)

		if client.signal != nil {
			client.signal.Close()
		}

		if client.tunnel != nil {
			client.tunnel.Close()
		}

		if client.file != nil {
			client.file.Close()
		}

		client.signals.Range(func(key, _ interface{}) bool {
			c := key.(*conn.Conn)
			c.Close()
			client.signals.Delete(key)
			return true
		})

		client.tunnels.Range(func(key, _ interface{}) bool {
			t := key.(*nps_mux.Mux)
			t.Close()
			client.tunnels.Delete(key)
			return true
		})

		s.Client.Delete(id)

		if file.GetDb().IsPubClient(id) {
			return
		}
		if c, err := file.GetDb().GetClient(id); err == nil {
			select {
			case s.CloseClient <- c.Id:
			default:
				logs.Warn("CloseClient channel is full, failed to send close signal for client %d", c.Id)
			}
		}
	}
}

// use different
func (s *Bridge) typeDeal(typeVal string, c *conn.Conn, id int, vs string) {
	isPub := file.GetDb().IsPubClient(id)
	switch typeVal {
	case common.WORK_MAIN:
		if isPub {
			c.Close()
			return
		}
		tcpConn, ok := c.Conn.(*net.TCPConn)
		if ok {
			// add tcp keep alive option for signal connection
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(5 * time.Second)
		}

		//the vKey connect by another, close the client of before
		if v, loaded := s.Client.LoadOrStore(id, NewClient(nil, nil, c, vs)); loaded {
			client := v.(*Client)
			if client.signal != nil {
				client.signal.WriteClose()
				client.signals.LoadOrStore(client.signal, struct{}{})
			}
			client.signal = c
			client.Version = vs
		}

		go s.GetHealthFromClient(id, c)
		logs.Info("clientId %d connection succeeded, address:%v ", id, c.Conn.RemoteAddr())

	case common.WORK_CHAN:
		muxConn := nps_mux.NewMux(c.Conn, s.tunnelType, s.disconnectTime)
		if v, loaded := s.Client.LoadOrStore(id, NewClient(muxConn, nil, nil, vs)); loaded {
			client := v.(*Client)
			if client.tunnel != nil {
				client.tunnels.LoadOrStore(client.tunnel, struct{}{})
			}
			client.tunnel = muxConn
		}

	case common.WORK_CONFIG:
		client, err := file.GetDb().GetClient(id)
		if err != nil || (!isPub && !client.ConfigConnAllow) {
			c.Close()
			return
		}
		binary.Write(c, binary.LittleEndian, isPub)
		go s.getConfig(c, isPub, client)

	case common.WORK_REGISTER:
		go s.register(c)

	case common.WORK_SECRET:
		if b, err := c.GetShortContent(32); err == nil {
			s.SecretChan <- conn.NewSecret(string(b), c)
		} else {
			logs.Error("secret error, failed to match the key successfully")
		}

	case common.WORK_FILE:
		muxConn := nps_mux.NewMux(c.Conn, s.tunnelType, s.disconnectTime)
		if v, loaded := s.Client.LoadOrStore(id, NewClient(nil, muxConn, nil, vs)); loaded {
			client := v.(*Client)
			if client.file != nil {
				client.tunnels.LoadOrStore(client.file, struct{}{})
			}
			client.file = muxConn
		}

	case common.WORK_P2P:
		// read md5 secret
		if b, err := c.GetShortContent(32); err != nil {
			logs.Error("p2p error, %v", err)
		} else if t := file.GetDb().GetTaskByMd5Password(string(b)); t == nil {
			logs.Error("p2p error, failed to match the key successfully")
		} else if v, ok := s.Client.Load(t.Client.Id); ok {
			serverPort := beego.AppConfig.String("p2p_port")
			if serverPort == "" {
				logs.Warn("get local udp addr error")
				return
			}
			serverIP := common.GetServerIp()
			svrAddr := common.BuildAddress(serverIP, serverPort)
			signalAddr := common.BuildAddress(serverIP, serverPort)
			remoteIP := net.ParseIP(common.GetIpByAddr(c.RemoteAddr().String()))
			if remoteIP != nil && (remoteIP.IsPrivate() || remoteIP.IsLoopback() || remoteIP.IsLinkLocalUnicast()) {
				svrAddr = common.BuildAddress(common.GetIpByAddr(c.LocalAddr().String()), serverPort)
			}
			client := v.(*Client)
			signalIP := net.ParseIP(common.GetIpByAddr(client.signal.RemoteAddr().String()))
			if signalIP != nil && (signalIP.IsPrivate() || signalIP.IsLoopback() || signalIP.IsLinkLocalUnicast()) {
				signalAddr = common.BuildAddress(common.GetIpByAddr(client.signal.LocalAddr().String()), serverPort)
			}
			client.signal.Write([]byte(common.NEW_UDP_CONN))
			client.signal.WriteLenContent([]byte(signalAddr))
			client.signal.WriteLenContent(b)
			c.WriteLenContent([]byte(svrAddr))
			logs.Trace("P2P: remoteIP=%s, svr1Addr=%s, clientIP=%s, svr2Addr=%s", remoteIP, svrAddr, signalIP, signalAddr)
		} else {
			return
		}
	}

	c.SetAlive()
	return
}

// register ip
func (s *Bridge) register(c *conn.Conn) {
	var hour int32
	if err := binary.Read(c, binary.LittleEndian, &hour); err == nil {
		ip := common.GetIpByAddr(c.Conn.RemoteAddr().String())
		s.Register.Store(ip, time.Now().Add(time.Hour*time.Duration(hour)))
		logs.Info("Registered IP: %s for %d hours", ip, hour)
	} else {
		logs.Warn("Failed to register IP: %v", err)
	}
}

func (s *Bridge) SendLinkInfo(clientId int, link *conn.Link, t *file.Tunnel) (target net.Conn, err error) {
	// if the proxy type is local
	if link.LocalProxy {
		target, err = net.Dial("tcp", link.Host)
		return
	}

	clientValue, ok := s.Client.Load(clientId)
	if !ok {
		err = errors.New(fmt.Sprintf("the client %d is not connect", clientId))
		return
	}

	client := clientValue.(*Client)
	// If IP is restricted, do IP verification
	if s.ipVerify {
		ip := common.GetIpByAddr(link.RemoteAddr)
		ipValue, ok := s.Register.Load(ip)
		if !ok {
			return nil, errors.New(fmt.Sprintf("The ip %s is not in the validation list", ip))
		}

		if !ipValue.(time.Time).After(time.Now()) {
			return nil, errors.New(fmt.Sprintf("The validity of the ip %s has expired", ip))
		}
	}

	var tunnel *nps_mux.Mux
	if t != nil && t.Mode == "file" {
		tunnel = client.file
	} else {
		tunnel = client.tunnel
	}

	if tunnel == nil {
		err = errors.New("the client connect error")
		return
	}

	target, err = tunnel.NewConn()
	if err != nil {
		return
	}

	if t != nil && t.Mode == "file" {
		//TODO if t.mode is file ,not use crypt or compress
		link.Crypt = false
		link.Compress = false
		return
	}

	if _, err = conn.NewConn(target).SendInfo(link, ""); err != nil {
		logs.Info("new connection error, the target %s refused to connect", link.Host)
		return
	}

	return
}

func (s *Bridge) ping() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			closedClients := make([]int, 0)

			s.Client.Range(func(key, value interface{}) bool {
				clientID := key.(int)
				client := value.(*Client)

				if clientID <= 0 {
					return true
				}

				if client == nil || client.signal == nil || client.tunnel == nil || client.tunnel.IsClose {
					client.retryTime++
					if client.retryTime >= 3 {
						logs.Trace("Stop client %d", clientID)
						closedClients = append(closedClients, clientID)
					}
				} else {
					client.retryTime = 0 // Reset retry count when the state is normal
				}
				return true
			})

			for _, clientId := range closedClients {
				logs.Info("the client %d closed", clientId)
				s.DelClient(clientId)
			}
		}
	}
}

// get config and add task from client config
func (s *Bridge) getConfig(c *conn.Conn, isPub bool, client *file.Client) {
	var fail bool
loop:
	for {
		flag, err := c.ReadFlag()
		if err != nil {
			break
		}

		switch flag {
		case common.WORK_STATUS:
			b, err := c.GetShortContent(64)
			if err != nil {
				break loop
			}

			id, err := file.GetDb().GetClientIdByBlake2bVkey(string(b))
			if err != nil {
				break loop
			}

			var strBuilder strings.Builder
			file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
				v := value.(*file.Host)
				if v.Client.Id == id {
					strBuilder.WriteString(v.Remark + common.CONN_DATA_SEQ)
				}
				return true
			})

			file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
				v := value.(*file.Tunnel)
				if _, ok := s.runList.Load(v.Id); ok && v.Client.Id == id {
					strBuilder.WriteString(v.Remark + common.CONN_DATA_SEQ)
				}
				return true
			})

			str := strBuilder.String()
			binary.Write(c, binary.LittleEndian, int32(len([]byte(str))))
			binary.Write(c, binary.LittleEndian, []byte(str))

		case common.NEW_CONF:
			client, err = c.GetConfigInfo()
			if err != nil {
				fail = true
				c.WriteAddFail()
				break loop
			}

			if err = file.GetDb().NewClient(client); err != nil {
				fail = true
				c.WriteAddFail()
				break loop
			}

			c.WriteAddOk()
			c.Write([]byte(client.VerifyKey))
			s.Client.Store(client.Id, NewClient(nil, nil, nil, ""))

		case common.NEW_HOST:
			h, err := c.GetHostInfo()
			if err != nil {
				fail = true
				c.WriteAddFail()
				break loop
			}

			h.Client = client
			if h.Location == "" {
				h.Location = "/"
			}

			if !client.HasHost(h) {
				if file.GetDb().IsHostExist(h) {
					fail = true
					c.WriteAddFail()
					break loop
				}
				file.GetDb().NewHost(h)
			}
			c.WriteAddOk()

		case common.NEW_TASK:
			t, err := c.GetTaskInfo()
			if err != nil {
				fail = true
				c.WriteAddFail()
				break loop
			}

			ports := common.GetPorts(t.Ports)
			targets := common.GetPorts(t.Target.TargetStr)
			if len(ports) > 1 && (t.Mode == "tcp" || t.Mode == "udp") && (len(ports) != len(targets)) {
				fail = true
				c.WriteAddFail()
				break loop
			} else if t.Mode == "secret" || t.Mode == "p2p" {
				ports = append(ports, 0)
			}

			if len(ports) == 0 {
				fail = true
				c.WriteAddFail()
				break loop
			}

			for i := 0; i < len(ports); i++ {
				tl := &file.Tunnel{
					Mode:         t.Mode,
					Port:         ports[i],
					ServerIp:     t.ServerIp,
					Client:       client,
					Password:     t.Password,
					LocalPath:    t.LocalPath,
					StripPre:     t.StripPre,
					MultiAccount: t.MultiAccount,
					Id:           int(file.GetDb().JsonDb.GetTaskId()),
					Status:       true,
					Flow:         new(file.Flow),
					NoStore:      true,
				}

				if len(ports) == 1 {
					tl.Target = t.Target
					tl.Remark = t.Remark
				} else {
					tl.Remark = fmt.Sprintf("%s_%d", t.Remark, tl.Port)
					if t.TargetAddr != "" {
						tl.Target = &file.Target{
							TargetStr: fmt.Sprintf("%s:%d", t.TargetAddr, targets[i]),
						}
					} else {
						tl.Target = &file.Target{
							TargetStr: strconv.Itoa(targets[i]),
						}
					}
				}

				if !client.HasTunnel(tl) {
					if err := file.GetDb().NewTask(tl); err != nil {
						logs.Warn("add task error: %v", err)
						fail = true
						c.WriteAddFail()
						break loop
					}

					if b := tool.TestServerPort(tl.Port, tl.Mode); !b && t.Mode != "secret" && t.Mode != "p2p" {
						fail = true
						c.WriteAddFail()
						break loop
					}

					s.OpenTask <- tl
				}
				c.WriteAddOk()
			}
		}
	}

	if fail && client != nil {
		s.DelClient(client.Id)
	}
	c.Close()
}
