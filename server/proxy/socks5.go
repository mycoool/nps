package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/conn"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/logs"
)

const (
	ipV4            = 1
	domainName      = 3
	ipV6            = 4
	connectMethod   = 1
	bindMethod      = 2
	associateMethod = 3
	// The maximum packet size of any udp Associate packet, based on ethernet's max size,
	// minus the IP and UDP headers. IPv4 has a 20 byte header, UDP adds an
	// additional 4 bytes.  This is a total overhead of 24 bytes.  Ethernet's
	// max packet size is 1500 bytes,  1500 - 24 = 1476.
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

//type Sock5ModeServer struct {
//	BaseServer
//	listener net.Listener
//}

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

	_, err := io.ReadFull(c, header)

	if err != nil {
		logs.Warn("illegal request %v", err)
		c.Close()
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
		c.Close()
	}
}

// reply
func (s *TunnelModeServer) sendReply(c net.Conn, rep uint8) {
	reply := []byte{
		5,
		rep,
		0,
		1,
	}

	localAddr := c.LocalAddr().String()
	localHost, localPort, _ := net.SplitHostPort(localAddr)
	ipBytes := net.ParseIP(localHost).To4()
	if ipBytes == nil {
		ipBytes = net.ParseIP("127.0.0.1").To4()
	}
	nPort, _ := strconv.Atoi(localPort)
	reply = append(reply, ipBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(nPort))
	reply = append(reply, portBytes...)

	c.Write(reply)
}

// do conn
func (s *TunnelModeServer) doConnect(c net.Conn, command uint8) {
	addrType := make([]byte, 1)
	c.Read(addrType)
	var host string
	switch addrType[0] {
	case ipV4:
		ipv4 := make(net.IP, net.IPv4len)
		c.Read(ipv4)
		host = ipv4.String()
	case ipV6:
		ipv6 := make(net.IP, net.IPv6len)
		c.Read(ipv6)
		host = ipv6.String()
	case domainName:
		var domainLen uint8
		binary.Read(c, binary.BigEndian, &domainLen)
		domain := make([]byte, domainLen)
		c.Read(domain)
		host = string(domain)
	default:
		s.sendReply(c, addrTypeNotSupported)
		return
	}

	var port uint16
	binary.Read(c, binary.BigEndian, &port)
	// connect to host
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	var ltype string
	if command == associateMethod {
		ltype = common.CONN_UDP
	} else {
		ltype = common.CONN_TCP
	}
	s.DealClient(conn.NewConn(c), s.task.Client, addr, nil, ltype, func() {
		s.sendReply(c, succeeded)
	}, []*file.Flow{s.task.Flow, s.task.Client.Flow}, s.task.Target.ProxyProtocol, s.task.Target.LocalProxy, s.task)
	return
}

// conn
func (s *TunnelModeServer) handleConnect(c net.Conn) {
	s.doConnect(c, connectMethod)
}

// passive mode
func (s *TunnelModeServer) handleBind(c net.Conn) {
}
func (s *TunnelModeServer) sendUdpReply(writeConn net.Conn, c net.Conn, rep uint8, serverIp string) {
	reply := []byte{
		5,
		rep,
		0,
		1,
	}
	localHost, localPort, _ := net.SplitHostPort(c.LocalAddr().String())
	localHost = serverIp
	ipBytes := net.ParseIP(localHost).To4()
	nPort, _ := strconv.Atoi(localPort)
	reply = append(reply, ipBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(nPort))
	reply = append(reply, portBytes...)
	writeConn.Write(reply)

}

func (s *TunnelModeServer) handleUDP(c net.Conn) {
	defer c.Close()
	addrType := make([]byte, 1)
	c.Read(addrType)
	var host string
	switch addrType[0] {
	case ipV4:
		ipv4 := make(net.IP, net.IPv4len)
		c.Read(ipv4)
		host = ipv4.String()
	case ipV6:
		ipv6 := make(net.IP, net.IPv6len)
		c.Read(ipv6)
		host = ipv6.String()
	case domainName:
		var domainLen uint8
		binary.Read(c, binary.BigEndian, &domainLen)
		domain := make([]byte, domainLen)
		c.Read(domain)
		host = string(domain)
	default:
		s.sendReply(c, addrTypeNotSupported)
		return
	}
	//读取端口
	var port uint16
	binary.Read(c, binary.BigEndian, &port)
	logs.Trace("%s %d", host, port)
	replyAddr, err := net.ResolveUDPAddr("udp", s.task.ServerIp+":0")
	if err != nil {
		logs.Error("build local reply addr error %v", err)
		return
	}
	reply, err := net.ListenUDP("udp", replyAddr)
	if err != nil {
		s.sendReply(c, addrTypeNotSupported)
		logs.Error("listen local reply udp port error")
		return
	}
	// reply the local addr
	s.sendUdpReply(c, reply, succeeded, common.GetServerIpByClientIp(c.RemoteAddr().(*net.TCPAddr).IP))
	defer reply.Close()
	// new a tunnel to client
	link := conn.NewLink("udp5", "", s.task.Client.Cnf.Crypt, s.task.Client.Cnf.Compress, c.RemoteAddr().String(), s.allowLocalProxy && s.task.Target.LocalProxy)
	target, err := s.bridge.SendLinkInfo(s.task.Client.Id, link, s.task)
	if err != nil {
		logs.Warn("get connection from client id %d  error %v", s.task.Client.Id, err)
		return
	}

	var clientAddr net.Addr
	// copy buffer
	go func() {
		b := common.BufPoolUdp.Get().([]byte)
		defer common.BufPoolUdp.Put(b)
		defer c.Close()

		for {
			n, laddr, err := reply.ReadFrom(b)
			if err != nil {
				logs.Debug("read data from %v err %v", reply.LocalAddr(), err)
				return
			}
			if clientAddr == nil {
				clientAddr = laddr
			}
			if _, err := target.Write(b[:n]); err != nil {
				logs.Debug("write data to client error %v", err)
				return
			}
		}
	}()

	go func() {
		var l int32
		b := common.BufPoolUdp.Get().([]byte)
		defer common.BufPoolUdp.Put(b)
		defer c.Close()
		for {
			if err := binary.Read(target, binary.LittleEndian, &l); err != nil || l >= common.PoolSizeUdp || l <= 0 {
				logs.Debug("read len bytes error %v", err)
				return
			}
			binary.Read(target, binary.LittleEndian, b[:l])
			if err != nil {
				logs.Warn("read data form client error %v", err)
				return
			}
			if _, err := reply.WriteTo(b[:l], clientAddr); err != nil {
				logs.Warn("write data to user %v", err)
				return
			}
		}
	}()

	b := common.BufPoolUdp.Get().([]byte)
	defer common.BufPoolUdp.Put(b)
	defer target.Close()
	for {
		_, err := c.Read(b)
		if err != nil {
			c.Close()
			return
		}
	}
}

// socks5 auth
func (s *TunnelModeServer) Auth(c net.Conn) error {
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(c, header, 2); err != nil {
		return err
	}
	if header[0] != userAuthVersion {
		return errors.New("auth method not supported")
	}
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(c, user, userLen); err != nil {
		return err
	}
	if _, err := c.Read(header[:1]); err != nil {
		return errors.New("failed to read password length")
	}
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(c, pass, passLen); err != nil {
		return err
	}

	if common.CheckAuthWithAccountMap(string(user), string(pass), s.task.Client.Cnf.U, s.task.Client.Cnf.P, file.GetAccountMap(s.task.MultiAccount), file.GetAccountMap(s.task.UserAuth)) {
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
	switch s.task.Mode {
	case "socks5":
		s.task.Mode = "mixProxy"
		s.task.HttpProxy = false
		s.task.Socks5Proxy = true
	case "httpProxy":
		s.task.Mode = "mixProxy"
		s.task.HttpProxy = true
		s.task.Socks5Proxy = false
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		logs.Warn("negotiation err %v", err)
		c.Close()
		return err
	}

	if version := buf[0]; version != 5 {
		method := string(buf)
		switch method {
		case "GE", "PO", "HE", "PU ", "DE", "OP", "CO", "TR", "PA", "PR", "MK", "MO", "LO", "UN", "RE", "AC", "SE", "LI":
			if !s.task.HttpProxy {
				logs.Warn("http proxy is disable, client %d request from: %v", s.task.Client.Id, c.RemoteAddr())
				c.Close()
				return errors.New("http proxy is disabled")
			}
			nConn := conn.NewConn(c)
			nConn.Rb = buf
			ss := NewTunnelModeServer(ProcessHttp, s.bridge, s.task)
			if err := ProcessHttp(nConn, ss); err != nil {
				logs.Warn("http proxy error: %v", err)
				return err
			}
			c.Close()
			return nil
		}
		logs.Trace("Socks5 Buf: %s", buf)
		logs.Warn("only support socks5 and http, request from: %v", c.RemoteAddr())
		c.Close()
		return errors.New("unknown protocol")
	}

	if !s.task.Socks5Proxy {
		logs.Warn("socks5 proxy is disable, client %d request from: %v", s.task.Client.Id, c.RemoteAddr())
		c.Close()
		return errors.New("socks5 proxy is disabled")
	}

	nMethods := buf[1]
	methods := make([]byte, nMethods)
	if len, err := c.Read(methods); len != int(nMethods) || err != nil {
		logs.Warn("wrong method")
		c.Close()
		return errors.New("wrong method")
	}
	if (s.task.Client.Cnf.U != "" && s.task.Client.Cnf.P != "") || (s.task.MultiAccount != nil && len(s.task.MultiAccount.AccountMap) > 0) || (s.task.UserAuth != nil && len(s.task.UserAuth.AccountMap) > 0) {
		buf[1] = UserPassAuth
		c.Write(buf)
		if err := s.Auth(c); err != nil {
			c.Close()
			logs.Warn("Validation failed: %v", err)
			return err
		}
	} else {
		buf[1] = 0
		c.Write(buf)
	}
	s.handleSocks5Request(c)
	return nil
}

/*
// start
func (s *TunnelModeServer) Start() error {
	return conn.NewTcpListenerAndProcess(common.BuildAddress(s.task.ServerIp, strconv.Itoa(s.task.Port)), func(c net.Conn) {
		if err := s.CheckFlowAndConnNum(s.task.Client); err != nil {
			logs.Warn("client id %d, task id %d, error %v, when socks5 connection", s.task.Client.Id, s.task.Id, err)
			c.Close()
			return
		}
		logs.Trace("New proxy (socks5/http) connection,client %d,remote address %v", s.task.Client.Id, c.RemoteAddr())
		s.handleConn(c)
		s.task.Client.CutConn()
	}, &s.listener)
}

// new
func NewSock5ModeServer(bridge NetBridge, task *file.Tunnel) *TunnelModeServer {
	allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy")
	s := new(Sock5ModeServer)
	s.bridge = bridge
	s.task = task
	s.allowLocalProxy = allowLocalProxy
	return s
}

// close
func (s *TunnelModeServer) Close() error {
	return s.listener.Close()
}
*/
