package client

import (
	"bufio"
	"bytes"
	"context"
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
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/lib/nps_mux"
	"github.com/xtaci/kcp-go/v5"
)

type TRPClient struct {
	svrAddr        string
	bridgeConnType string
	proxyUrl       string
	vKey           string
	p2pAddr        map[string]string
	tunnel         *nps_mux.Mux
	signal         *conn.Conn
	ticker         *time.Ticker
	cnf            *config.Config
	disconnectTime int
	ctx            context.Context
	cancel         context.CancelFunc
	healthChecker  *HealthChecker
	once           sync.Once
}

// new client
func NewRPClient(svraddr string, vKey string, bridgeConnType string, proxyUrl string, cnf *config.Config, disconnectTime int) *TRPClient {
	return &TRPClient{
		svrAddr:        svraddr,
		p2pAddr:        make(map[string]string, 0),
		vKey:           vKey,
		bridgeConnType: bridgeConnType,
		proxyUrl:       proxyUrl,
		cnf:            cnf,
		disconnectTime: disconnectTime,
		once:           sync.Once{},
	}
}

var NowStatus int
var HasFailed = false

// start
func (s *TRPClient) Start() {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.Close()
	NowStatus = 0
	c, err := NewConn(s.bridgeConnType, s.vKey, s.svrAddr, common.WORK_MAIN, s.proxyUrl)
	if err != nil {
		HasFailed = true
		logs.Error("The connection server failed and will be reconnected in five seconds, error %v", err)
		return
	}
	logs.Info("Successful connection with server %s", s.svrAddr)
	s.signal = c
	//start a channel connection
	go s.newChan()
	//monitor the connection
	go s.ping()
	//start health check if it's open
	if s.cnf != nil && len(s.cnf.Healths) > 0 {
		s.healthChecker = NewHealthChecker(s.ctx, s.cnf.Healths, s.signal)
		s.healthChecker.Start()
	}
	NowStatus = 1
	//msg connection, eg udp
	s.handleMain()
}

// handle main connection
func (s *TRPClient) handleMain() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		flags, err := s.signal.ReadFlag()
		if err != nil {
			logs.Error("Accept server data error %v, end this service", err)
			return
		}
		switch flags {
		case common.NEW_UDP_CONN:
			//read server udp addr and password
			if lAddr, err := s.signal.GetShortLenContent(); err != nil {
				logs.Warn("%v", err)
				return
			} else if pwd, err := s.signal.GetShortLenContent(); err == nil {
				rAddr := string(lAddr)
				remoteIP := net.ParseIP(common.GetIpByAddr(s.signal.RemoteAddr().String()))
				if remoteIP != nil && (remoteIP.IsPrivate() || remoteIP.IsLoopback() || remoteIP.IsLinkLocalUnicast()) {
					rAddr = common.BuildAddress(remoteIP.String(), strconv.Itoa(common.GetPortByAddr(rAddr)))
				}
				var localAddr string
				//The local port remains unchanged for a certain period of time
				if v, ok := s.p2pAddr[crypt.Md5(string(pwd)+strconv.Itoa(int(time.Now().Unix()/100)))]; !ok {
					if strings.Contains(rAddr, "]:") {
						tmpConn, err := common.GetLocalUdp6Addr()
						if err != nil {
							logs.Error("%v", err)
							return
						}
						localAddr = tmpConn.LocalAddr().String()
					} else {
						tmpConn, err := common.GetLocalUdp4Addr()
						if err != nil {
							logs.Error("%v", err)
							return
						}
						localAddr = tmpConn.LocalAddr().String()
					}
				} else {
					localAddr = v
				}
				go s.newUdpConn(localAddr, rAddr, string(pwd))
			}
		}
	}
	s.Close()
}

func (s *TRPClient) newUdpConn(localAddr, rAddr string, md5Password string) {
	var localConn net.PacketConn
	var err error
	var remoteAddress string
	//logs.Debug("newUdpConn %s %s", localAddr, rAddr)
	if remoteAddress, localConn, err = handleP2PUdp(s.ctx, localAddr, rAddr, md5Password, common.WORK_P2P_PROVIDER); err != nil {
		logs.Error("%v", err)
		return
	}
	defer localConn.Close()
	l, err := kcp.ServeConn(nil, 150, 3, localConn)
	if err != nil {
		logs.Error("%v", err)
		return
	}
	defer l.Close()
	logs.Trace("start local p2p udp listen, local address %v", localConn.LocalAddr())
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		udpTunnel, err := l.AcceptKCP()
		if err != nil {
			logs.Error("acceptKCP failed on listener %v waiting for remote %s: %v", localConn.LocalAddr(), remoteAddress, err)
			return
		}
		if udpTunnel.RemoteAddr().String() == string(remoteAddress) {
			conn.SetUdpSession(udpTunnel)
			logs.Trace("successful connection with client ,address %v", udpTunnel.RemoteAddr())
			//read link info from remote
			conn.Accept(nps_mux.NewMux(udpTunnel, s.bridgeConnType, s.disconnectTime), func(c net.Conn) {
				go s.handleChan(c)
			})
			return
		}
	}
}

// pmux tunnel
func (s *TRPClient) newChan() {
	tunnel, err := NewConn(s.bridgeConnType, s.vKey, s.svrAddr, common.WORK_CHAN, s.proxyUrl)
	if err != nil {
		logs.Error("connect to %s error: %v", s.svrAddr, err)
		return
	}
	s.tunnel = nps_mux.NewMux(tunnel.Conn, s.bridgeConnType, s.disconnectTime)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		src, err := s.tunnel.Accept()
		if err != nil {
			logs.Warn("%v", err)
			s.Close()
			return
		}
		go s.handleChan(src)
	}
}

func (s *TRPClient) handleChan(src net.Conn) {
	lk, err := conn.NewConn(src).GetLinkInfo()
	if err != nil || lk == nil {
		src.Close()
		logs.Error("get connection info from server error %v", err)
		return
	}
	//host for target processing
	lk.Host = common.FormatAddress(lk.Host)
	//if Conn type is http, read the request and log
	if lk.ConnType == "http" {
		if targetConn, err := net.DialTimeout(common.CONN_TCP, lk.Host, lk.Option.Timeout); err != nil {
			logs.Warn("connect to %s error %v", lk.Host, err)
			src.Close()
		} else {
			srcConn := conn.GetConn(src, lk.Crypt, lk.Compress, nil, false)
			go func() {
				common.CopyBuffer(srcConn, targetConn)
				srcConn.Close()
				targetConn.Close()
			}()
			for {
				select {
				case <-s.ctx.Done():
					srcConn.Close()
					targetConn.Close()
					return
				default:
				}
				if r, err := http.ReadRequest(bufio.NewReader(srcConn)); err != nil {
					logs.Error("http read error: %v", err)
					srcConn.Close()
					targetConn.Close()
					return
				} else {
					remoteAddr := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
					if len(remoteAddr) == 0 {
						remoteAddr = r.RemoteAddr
					}
					logs.Trace("http request, method %s, host %s, url %s, remote address %s", r.Method, r.Host, r.URL.Path, remoteAddr)
					r.Write(targetConn)
				}
			}
		}
		return
	}
	if lk.ConnType == "udp5" {
		logs.Trace("new %s connection with the goal of %s, remote address:%s", lk.ConnType, lk.Host, lk.RemoteAddr)
		s.handleUdp(src)
	}
	//connect to target if conn type is tcp or udp
	if targetConn, err := net.DialTimeout(lk.ConnType, lk.Host, lk.Option.Timeout); err != nil {
		logs.Warn("connect to %s error %v", lk.Host, err)
		src.Close()
	} else {
		logs.Trace("new %s connection with the goal of %s, remote address:%s", lk.ConnType, lk.Host, lk.RemoteAddr)
		conn.CopyWaitGroup(src, targetConn, lk.Crypt, lk.Compress, nil, nil, false, 0, nil, nil)
	}
}

func (s *TRPClient) handleUdp(serverConn net.Conn) {
	// bind a local udp port
	local, err := net.ListenUDP("udp", nil)
	defer local.Close()
	defer serverConn.Close()
	if err != nil {
		logs.Error("bind local udp port error %v", err)
		return
	}
	go func() {
		defer serverConn.Close()
		b := common.BufPoolUdp.Get().([]byte)
		defer common.BufPoolUdp.Put(b)
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			n, raddr, err := local.ReadFrom(b)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					logs.Info("local UDP closed, exiting goroutine")
					return
				}
				if ne, ok := err.(net.Error); ok && (ne.Temporary() || ne.Timeout()) {
					logs.Warn("temporary UDP read error, retrying: %v", err)
					time.Sleep(1 * time.Millisecond)
					continue
				}
				logs.Error("read data from remote server error %v", err)
				return
			}
			buf := bytes.Buffer{}
			dgram := common.NewUDPDatagram(common.NewUDPHeader(0, 0, common.ToSocksAddr(raddr)), b[:n])
			dgram.Write(&buf)
			b, err := conn.GetLenBytes(buf.Bytes())
			if err != nil {
				logs.Warn("get len bytes error %v", err)
				continue
			}
			if _, err := serverConn.Write(b); err != nil {
				logs.Error("write data to remote error %v", err)
				return
			}
		}
	}()
	b := common.BufPoolUdp.Get().([]byte)
	defer common.BufPoolUdp.Put(b)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		n, err := serverConn.Read(b)
		if err != nil {
			logs.Error("read udp data from server error %v", err)
			return
		}
		udpData, err := common.ReadUDPDatagram(bytes.NewReader(b[:n]))
		if err != nil {
			logs.Error("unpack data error %v", err)
			return
		}
		raddr, err := net.ResolveUDPAddr("udp", udpData.Header.Addr.String())
		if err != nil {
			logs.Error("build remote addr err %v", err)
			continue // drop silently
		}
		_, err = local.WriteTo(udpData.Data, raddr)
		if err != nil {
			logs.Error("write data to remote %v error %v", raddr, err)
			return
		}
	}
}

// Whether the monitor channel is closed
func (s *TRPClient) ping() {
	s.ticker = time.NewTicker(time.Second * 5)
	for {
		select {
		case <-s.ticker.C:
			if s.tunnel == nil || s.tunnel.IsClose {
				s.Close()
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *TRPClient) Close() {
	s.once.Do(s.closing)
}

func (s *TRPClient) closing() {
	NowStatus = 0
	if s.healthChecker != nil {
		s.healthChecker.Stop()
	}
	s.cancel()
	if s.tunnel != nil {
		_ = s.tunnel.Close()
	}
	if s.signal != nil {
		_ = s.signal.Close()
	}
	if s.ticker != nil {
		s.ticker.Stop()
	}
}
