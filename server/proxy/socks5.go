package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/transport"
)

const (
	ipV4            = 1
	domainName      = 3
	ipV6            = 4
	connectMethod   = 1
	bindMethod      = 2
	associateMethod = 3
	// The maximum packet size of any udp Associate packet, based on ethernet's max size,
	// minus the IP and UDP headers. IPv4 has a 20 byte header, UDP adds another 4 bytes.
	// This is a total overhead of 24 bytes. Ethernet's max packet size is 1500 bytes,
	// 1500 - 24 = 1476.
	maxUDPPacketSize = 1476
)

const (
	succeeded uint8 = iota
	serverFailure
	notAllowed
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

const (
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

// req
func (s *TunnelModeServer) handleSocks5Request(c net.Conn) {
	/*
		The SOCKS request is formed as follows:
		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	*/
	header := make([]byte, 3)
	if _, err := io.ReadFull(c, header); err != nil {
		logs.Warn("illegal request (head) %v", err)
		_ = c.Close()
		return
	}
	// Strict check: VER==5, RSV==0
	if header[0] != 5 || header[2] != 0 {
		logs.Warn("illegal request ver/rsv: ver=%d rsv=%d", header[0], header[2])
		s.sendReply(c, commandNotSupported)
		_ = c.Close()
		return
	}

	switch header[1] {
	case connectMethod:
		s.handleConnect(c)
	case bindMethod:
		s.handleBind(c)
	case associateMethod:
		s.handleUDP(c)
	default:
		s.sendReply(c, commandNotSupported)
		_ = c.Close()
	}
}

// reply
func (s *TunnelModeServer) sendReply(c net.Conn, rep uint8) {
	localAddr := c.LocalAddr().String()
	localHost, localPort, _ := net.SplitHostPort(localAddr)
	ip := net.ParseIP(localHost)

	var atype byte
	var addrBytes []byte
	if v4 := ip.To4(); v4 != nil {
		atype = ipV4
		addrBytes = v4
	} else if v6 := ip.To16(); v6 != nil {
		atype = ipV6
		addrBytes = v6
	} else {
		atype = ipV4
		addrBytes = net.IPv4(127, 0, 0, 1).To4()
	}

	nPort, _ := strconv.Atoi(localPort)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(nPort))

	// VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	reply := []byte{5, rep, 0, atype}
	reply = append(reply, addrBytes...)
	reply = append(reply, portBytes...)

	_, _ = c.Write(reply)
}

// conn - CONNECT
func (s *TunnelModeServer) handleConnect(c net.Conn) {
	addrType := make([]byte, 1)
	if _, err := io.ReadFull(c, addrType); err != nil {
		s.sendReply(c, addrTypeNotSupported)
		return
	}
	var host string
	switch addrType[0] {
	case ipV4:
		ipv4 := make(net.IP, net.IPv4len)
		if _, err := io.ReadFull(c, ipv4); err != nil {
			s.sendReply(c, addrTypeNotSupported)
			return
		}
		host = ipv4.String()
	case ipV6:
		ipv6 := make(net.IP, net.IPv6len)
		if _, err := io.ReadFull(c, ipv6); err != nil {
			s.sendReply(c, addrTypeNotSupported)
			return
		}
		host = ipv6.String()
	case domainName:
		var domainLen uint8
		if err := binary.Read(c, binary.BigEndian, &domainLen); err != nil || domainLen == 0 {
			s.sendReply(c, addrTypeNotSupported)
			return
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(c, domain); err != nil {
			s.sendReply(c, addrTypeNotSupported)
			return
		}
		host = string(domain)
	default:
		s.sendReply(c, addrTypeNotSupported)
		return
	}

	var port uint16
	if err := binary.Read(c, binary.BigEndian, &port); err != nil {
		s.sendReply(c, addrTypeNotSupported)
		return
	}

	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	_ = s.DealClient(conn.NewConn(c), s.Task.Client, addr, nil, common.CONN_TCP, func() {
		s.sendReply(c, succeeded)
	}, []*file.Flow{s.Task.Flow, s.Task.Client.Flow}, 0, s.Task.Target.LocalProxy, s.Task)
}

// passive mode
func (s *TunnelModeServer) handleBind(c net.Conn) {
	s.sendReply(c, commandNotSupported)
	_ = c.Close()
}

func (s *TunnelModeServer) sendUdpReply(writeConn net.Conn, replyUDP *net.UDPConn, rep uint8, clientIP net.IP) {
	wantV6 := clientIP != nil && clientIP.To4() == nil

	var ipToUse net.IP

	if la, ok := replyUDP.LocalAddr().(*net.UDPAddr); ok && la != nil && la.IP != nil && !common.IsZeroIP(la.IP) {
		if (la.IP.To4() == nil) == wantV6 {
			ipToUse = la.IP
		}
	}

	if ipToUse == nil {
		if eip := common.PickEgressIPFor(clientIP); eip != nil && (eip.To4() == nil) == wantV6 {
			ipToUse = eip
		}
	}

	if ipToUse == nil {
		if wantV6 {
			ipToUse = net.IPv6loopback
		} else {
			ipToUse = net.IPv4(127, 0, 0, 1)
		}
	}

	var atype byte
	var addrBytes []byte
	if v4 := ipToUse.To4(); v4 != nil {
		atype = ipV4
		addrBytes = v4
	} else {
		atype = ipV6
		addrBytes = ipToUse.To16()
	}

	la := replyUDP.LocalAddr().(*net.UDPAddr)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(la.Port))

	// VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	reply := []byte{5, rep, 0, atype}
	reply = append(reply, addrBytes...)
	reply = append(reply, portBytes...)
	_, _ = writeConn.Write(reply)
}

func (s *TunnelModeServer) handleUDP(c net.Conn) {
	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
		_ = transport.SetTcpKeepAliveParams(tcpConn, 15, 15, 3)
	}
	defer c.Close()

	addrType := make([]byte, 1)
	if _, err := io.ReadFull(c, addrType); err != nil {
		s.sendReply(c, addrTypeNotSupported)
		return
	}
	var host string
	switch addrType[0] {
	case ipV4:
		ipv4 := make(net.IP, net.IPv4len)
		if _, err := io.ReadFull(c, ipv4); err != nil {
			s.sendReply(c, addrTypeNotSupported)
			return
		}
		host = ipv4.String()
	case ipV6:
		ipv6 := make(net.IP, net.IPv6len)
		if _, err := io.ReadFull(c, ipv6); err != nil {
			s.sendReply(c, addrTypeNotSupported)
			return
		}
		host = ipv6.String()
	case domainName:
		var domainLen uint8
		if err := binary.Read(c, binary.BigEndian, &domainLen); err != nil || domainLen == 0 {
			s.sendReply(c, addrTypeNotSupported)
			return
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(c, domain); err != nil {
			s.sendReply(c, addrTypeNotSupported)
			return
		}
		host = string(domain)
	default:
		s.sendReply(c, addrTypeNotSupported)
		return
	}
	// read port
	var port uint16
	if err := binary.Read(c, binary.BigEndian, &port); err != nil {
		s.sendReply(c, addrTypeNotSupported)
		return
	}
	logs.Trace("ASSOCIATE %s:%d", host, port)

	// get listen addr
	var clientIP net.IP
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok && ta != nil {
		clientIP = ta.IP
	}
	network, localAddr := common.BuildUdpBindAddr(s.Task.ServerIp, clientIP)

	reply, err := net.ListenUDP(network, localAddr)
	if err != nil {
		s.sendReply(c, addrTypeNotSupported)
		logs.Error("listen local reply udp port error: %v (network=%s, localAddr=%v)", err, network, localAddr)
		return
	}
	defer reply.Close()

	// reply the local addr
	//clientIP := c.RemoteAddr().(*net.TCPAddr).IP
	s.sendUdpReply(c, reply, succeeded, clientIP)

	// new a tunnel to client
	link := conn.NewLink("udp5", "", s.Task.Client.Cnf.Crypt, s.Task.Client.Cnf.Compress, c.RemoteAddr().String(), s.AllowLocalProxy && s.Task.Target.LocalProxy)
	link.Option.Timeout = time.Second * 180

	target, err := s.Bridge.SendLinkInfo(s.Task.Client.Id, link, s.Task)
	if err != nil {
		logs.Warn("get connection from client Id %d error: %v", s.Task.Client.Id, err)
		return
	}
	defer target.Close()

	timeoutConn := conn.NewTimeoutConn(target, link.Option.Timeout)
	defer timeoutConn.Close()
	flowConn := conn.NewFlowConn(timeoutConn, s.Task.Flow, s.Task.Client.Flow)

	framed := conn.WrapFramed(flowConn)

	var clientIPSeen net.IP
	var clientAddr atomic.Pointer[net.UDPAddr]

	// local UDP -> tunnel
	go func() {
		b := common.BufPoolMax.Get().([]byte)
		defer common.PutBufPoolMax(b)

		for {
			n, lAddr, err := reply.ReadFromUDP(b)
			if err != nil {
				logs.Debug("read data from %v err %v", reply.LocalAddr(), err)
				_ = c.Close()
				_ = flowConn.Close()
				return
			}
			if clientIPSeen == nil {
				clientIPSeen = common.NormalizeIP(lAddr.IP)
			}
			if !common.NormalizeIP(lAddr.IP).Equal(clientIPSeen) {
				logs.Debug("ignore udp from unexpected ip: %v", lAddr.IP)
				continue
			}
			clientAddr.Store(lAddr)

			if n >= 3 && b[2] != 0 {
				logs.Warn("socks5 udp frag not supported, drop (frag=%d)", b[2])
				continue
			}

			if n > conn.MaxFramePayload {
				logs.Debug("udp datagram too large: %d > %d (drop)", n, conn.MaxFramePayload)
				continue
			}
			if _, err := framed.Write(b[:n]); err != nil {
				logs.Debug("write udp frame to tunnel error %v", err)
				_ = c.Close()
				_ = flowConn.Close()
				return
			}
		}
	}()

	// tunnel -> local UDP
	go func() {
		b := common.BufPoolMax.Get().([]byte)
		defer common.PutBufPoolMax(b)

		for {
			n, err := framed.Read(b)
			if err != nil || n <= 0 || n > len(b) {
				logs.Debug("read udp frame from tunnel error %v", err)
				_ = c.Close()
				_ = flowConn.Close()
				return
			}
			if addr := clientAddr.Load(); addr != nil {
				if _, err := reply.WriteTo(b[:n], addr); err != nil {
					logs.Warn("write data to user %v", err)
					_ = c.Close()
					_ = flowConn.Close()
					return
				}
			}
		}
	}()

	b := common.BufPoolMax.Get().([]byte)
	defer common.PutBufPoolMax(b)
	for {
		if _, err := c.Read(b); err != nil {
			_ = flowConn.Close()
			return
		}
	}
}

func (s *TunnelModeServer) SocksAuth(c net.Conn) error {
	header := []byte{0, 0}
	if _, err := io.ReadFull(c, header); err != nil {
		return err
	}
	if header[0] != userAuthVersion {
		return errors.New("auth method not supported")
	}
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadFull(c, user); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, header[:1]); err != nil {
		return errors.New("failed to read password length")
	}
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadFull(c, pass); err != nil {
		return err
	}

	if common.CheckAuthWithAccountMap(string(user), string(pass), s.Task.Client.Cnf.U, s.Task.Client.Cnf.P, file.GetAccountMap(s.Task.MultiAccount), file.GetAccountMap(s.Task.UserAuth)) {
		if _, err := c.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return err
		}
		return nil
	} else {
		if _, err := c.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return err
		}
		return errors.New("auth failed")
	}
}

func ProcessMix(c *conn.Conn, s *TunnelModeServer) error {
	switch s.Task.Mode {
	case "socks5":
		s.Task.Mode = "mixProxy"
		s.Task.HttpProxy = false
		s.Task.Socks5Proxy = true
	case "httpProxy":
		s.Task.Mode = "mixProxy"
		s.Task.HttpProxy = true
		s.Task.Socks5Proxy = false
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		logs.Warn("negotiation err %v", err)
		_ = c.Close()
		return err
	}

	if version := buf[0]; version != 5 {
		method := string(buf)
		switch method {
		case "GE", "PO", "HE", "PU ", "DE", "OP", "CO", "TR", "PA", "PR", "MK", "MO", "LO", "UN", "RE", "AC", "SE", "LI":
			if !s.Task.HttpProxy {
				logs.Warn("http proxy is disable, client %d request from: %v", s.Task.Client.Id, c.RemoteAddr())
				_ = c.Close()
				return errors.New("http proxy is disabled")
			}
			if err := ProcessHttp(c.SetRb(buf), s); err != nil {
				logs.Warn("http proxy error: %v", err)
				_ = c.Close()
				return err
			}
			_ = c.Close()
			return nil
		}
		logs.Trace("Socks5 Buf: %s", buf)
		logs.Warn("only support socks5 and http, request from: %v", c.RemoteAddr())
		_ = c.Close()
		return errors.New("unknown protocol")
	}

	if !s.Task.Socks5Proxy {
		logs.Warn("socks5 proxy is disable, client %d request from: %v", s.Task.Client.Id, c.RemoteAddr())
		_ = c.Close()
		return errors.New("socks5 proxy is disabled")
	}

	nMethods := buf[1]
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		logs.Warn("wrong method")
		_ = c.Close()
		return errors.New("wrong method")
	}
	supports := func(m byte) bool {
		for _, x := range methods {
			if x == m {
				return true
			}
		}
		return false
	}
	needAuth := (s.Task.Client.Cnf.U != "" && s.Task.Client.Cnf.P != "") ||
		(s.Task.MultiAccount != nil && len(s.Task.MultiAccount.AccountMap) > 0) ||
		(s.Task.UserAuth != nil && len(s.Task.UserAuth.AccountMap) > 0)

	if needAuth {
		if !supports(UserPassAuth) {
			_, _ = c.Write([]byte{5, 0xFF})
			_ = c.Close()
			return errors.New("no acceptable authentication method")
		}
		_, _ = c.Write([]byte{5, UserPassAuth})
		if err := s.SocksAuth(c); err != nil {
			_ = c.Close()
			logs.Warn("Validation failed: %v", err)
			return err
		}
	} else {
		if !supports(0x00) {
			_, _ = c.Write([]byte{5, 0xFF})
			_ = c.Close()
			return errors.New("no acceptable method (no-auth not offered)")
		}
		_, _ = c.Write([]byte{5, 0x00})
	}
	s.handleSocks5Request(c)
	return nil
}
