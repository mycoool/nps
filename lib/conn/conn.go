package conn

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/crypt"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/goroutine"
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/lib/pmux"
	"github.com/mycoool/nps/lib/rate"
	"github.com/xtaci/kcp-go/v5"
)

var LocalTCPAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}

type Conn struct {
	Conn net.Conn
	Rb   []byte
}

// new conn
func NewConn(conn net.Conn) *Conn {
	return &Conn{Conn: conn}
}

func (s *Conn) readRequest(buf []byte) (n int, err error) {
	var rd int
	for {
		rd, err = s.Read(buf[n:])
		if err != nil {
			return
		}
		n += rd
		if n < 4 {
			continue
		}
		if string(buf[n-4:n]) == "\r\n\r\n" {
			return
		}
		// buf is full, can't contain the request
		if n == cap(buf) {
			err = io.ErrUnexpectedEOF
			return
		}
	}
}

// get host 、connection type、method...from connection
func (s *Conn) GetHost() (method, address string, rb []byte, err error, r *http.Request) {
	var b [32 * 1024]byte
	var n int
	if n, err = s.readRequest(b[:]); err != nil {
		return
	}
	rb = b[:n]
	r, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(rb)))
	if err != nil {
		return
	}
	hostPortURL, err := url.Parse(r.Host)
	if err != nil {
		address = r.Host
		err = nil
		return
	}
	if hostPortURL.Opaque == "443" {
		if strings.Index(r.Host, ":") == -1 {
			address = r.Host + ":443"
		} else {
			address = r.Host
		}
	} else {
		if strings.Index(r.Host, ":") == -1 {
			address = r.Host + ":80"
		} else {
			address = r.Host
		}
	}
	return
}

func (s *Conn) GetShortLenContent() (b []byte, err error) {
	var l int
	if l, err = s.GetLen(); err != nil {
		return
	}
	if l < 0 || l > 32<<10 {
		err = errors.New("read length error")
		return
	}
	return s.GetShortContent(l)
}

func (s *Conn) GetShortContent(l int) (b []byte, err error) {
	buf := make([]byte, l)
	return buf, binary.Read(s, binary.LittleEndian, &buf)
}

// 读取指定长度内容
func (s *Conn) ReadLen(cLen int, buf []byte) (int, error) {
	if cLen > len(buf) || cLen <= 0 {
		return 0, errors.New("长度错误" + strconv.Itoa(cLen))
	}
	if n, err := io.ReadFull(s, buf[:cLen]); err != nil || n != cLen {
		return n, errors.New("Error reading specified length " + err.Error())
	}
	return cLen, nil
}

func (s *Conn) GetLen() (int, error) {
	var l int32
	err := binary.Read(s, binary.LittleEndian, &l)
	return int(l), err
}

func (s *Conn) WriteLenContent(buf []byte) (err error) {
	var b []byte
	if b, err = GetLenBytes(buf); err != nil {
		return
	}
	return binary.Write(s.Conn, binary.LittleEndian, b)
}

// read flag
func (s *Conn) ReadFlag() (string, error) {
	buf := make([]byte, 4)
	return string(buf), binary.Read(s, binary.LittleEndian, &buf)
}

// set alive
func (s *Conn) SetAlive() {
	switch s.Conn.(type) {
	case *kcp.UDPSession:
		s.Conn.(*kcp.UDPSession).SetReadDeadline(time.Time{})
	case *net.TCPConn:
		s.Conn.(*net.TCPConn).SetReadDeadline(time.Time{})
	case *pmux.PortConn:
		s.Conn.(*pmux.PortConn).SetReadDeadline(time.Time{})
	case *tls.Conn:
		s.Conn.(*tls.Conn).SetReadDeadline(time.Time{})
	case *TlsConn:
		s.Conn.(*TlsConn).SetReadDeadline(time.Time{})
	default:
		if conn, ok := s.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			conn.SetReadDeadline(time.Time{})
		}
	}
}

// set read deadline
func (s *Conn) SetReadDeadlineBySecond(t time.Duration) {
	switch s.Conn.(type) {
	case *kcp.UDPSession:
		s.Conn.(*kcp.UDPSession).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	case *net.TCPConn:
		s.Conn.(*net.TCPConn).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	case *pmux.PortConn:
		s.Conn.(*pmux.PortConn).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	case *tls.Conn:
		s.Conn.(*tls.Conn).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	case *TlsConn:
		s.Conn.(*TlsConn).SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
	default:
		if conn, ok := s.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			conn.SetReadDeadline(time.Now().Add(time.Duration(t) * time.Second))
		}
	}
}

// get link info from conn
func (s *Conn) GetLinkInfo() (lk *Link, err error) {
	err = s.getInfo(&lk)
	return
}

// send info for link
func (s *Conn) SendHealthInfo(info, status string) (int, error) {
	raw := bytes.NewBuffer([]byte{})
	common.BinaryWrite(raw, info, status)
	return s.Write(raw.Bytes())
}

// get health info from conn
func (s *Conn) GetHealthInfo() (info string, status bool, err error) {
	var l int
	buf := common.BufPoolMax.Get().([]byte)
	defer common.PutBufPoolMax(buf)
	if l, err = s.GetLen(); err != nil {
		return
	} else if _, err = s.ReadLen(l, buf); err != nil {
		return
	} else {
		arr := strings.Split(string(buf[:l]), common.CONN_DATA_SEQ)
		if len(arr) >= 2 {
			return arr[0], common.GetBoolByStr(arr[1]), nil
		}
	}
	return "", false, errors.New("receive health info error")
}

// get task info
func (s *Conn) GetHostInfo() (h *file.Host, err error) {
	err = s.getInfo(&h)
	h.Id = int(file.GetDb().JsonDb.GetHostId())
	h.Flow = new(file.Flow)
	h.NoStore = true
	return
}

// get task info
func (s *Conn) GetConfigInfo() (c *file.Client, err error) {
	err = s.getInfo(&c)
	c.NoStore = true
	c.Status = true
	if c.Flow == nil {
		c.Flow = new(file.Flow)
	}
	c.NoDisplay = false
	return
}

// get task info
func (s *Conn) GetTaskInfo() (t *file.Tunnel, err error) {
	err = s.getInfo(&t)
	t.Id = int(file.GetDb().JsonDb.GetTaskId())
	t.NoStore = true
	t.Flow = new(file.Flow)
	return
}

// send  info
func (s *Conn) SendInfo(t interface{}, flag string) (int, error) {
	/*
		The task info is formed as follows:
		+----+-----+---------+
		|type| len | content |
		+----+---------------+
		| 4  |  4  |   ...   |
		+----+---------------+
	*/
	raw := bytes.NewBuffer([]byte{})
	if flag != "" {
		binary.Write(raw, binary.LittleEndian, []byte(flag))
	}
	b, err := json.Marshal(t)
	if err != nil {
		return 0, err
	}
	lenBytes, err := GetLenBytes(b)
	if err != nil {
		return 0, err
	}
	binary.Write(raw, binary.LittleEndian, lenBytes)
	return s.Write(raw.Bytes())
}

// get task info
func (s *Conn) getInfo(t interface{}) (err error) {
	var l int
	buf := common.BufPoolMax.Get().([]byte)
	defer common.PutBufPoolMax(buf)
	if l, err = s.GetLen(); err != nil {
		return
	} else if _, err = s.ReadLen(l, buf); err != nil {
		return
	} else {
		json.Unmarshal(buf[:l], &t)
	}
	return
}

// close
func (s *Conn) Close() error {
	return s.Conn.Close()
}

// write
func (s *Conn) Write(b []byte) (int, error) {
	if s == nil {
		return -1, errors.New("connection error")
	}
	return s.Conn.Write(b)
}

// read
func (s *Conn) Read(b []byte) (n int, err error) {
	if s.Rb != nil {
		//if the rb is not nil ,read rb first
		if len(s.Rb) > 0 {
			n = copy(b, s.Rb)
			s.Rb = s.Rb[n:]
			return
		}
		s.Rb = nil
	}
	return s.Conn.Read(b)
}

// write sign flag
func (s *Conn) WriteClose() (int, error) {
	return s.Write([]byte(common.RES_CLOSE))
}

// write main
func (s *Conn) WriteMain() (int, error) {
	return s.Write([]byte(common.WORK_MAIN))
}

// write main
func (s *Conn) WriteConfig() (int, error) {
	return s.Write([]byte(common.WORK_CONFIG))
}

// write chan
func (s *Conn) WriteChan() (int, error) {
	return s.Write([]byte(common.WORK_CHAN))
}

// get task or host result of add
func (s *Conn) GetAddStatus() (b bool) {
	binary.Read(s.Conn, binary.LittleEndian, &b)
	return
}

func (s *Conn) WriteAddOk() error {
	return binary.Write(s.Conn, binary.LittleEndian, true)
}

func (s *Conn) WriteAddFail() error {
	defer s.Close()
	return binary.Write(s.Conn, binary.LittleEndian, false)
}

func (s *Conn) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s *Conn) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

func (s *Conn) SetDeadline(t time.Time) error {
	return s.Conn.SetDeadline(t)
}

func (s *Conn) SetWriteDeadline(t time.Time) error {
	return s.Conn.SetWriteDeadline(t)
}

func (s *Conn) SetReadDeadline(t time.Time) error {
	return s.Conn.SetReadDeadline(t)
}

// get the assembled amount data(len 4 and content)
func GetLenBytes(buf []byte) (b []byte, err error) {
	raw := bytes.NewBuffer([]byte{})
	if err = binary.Write(raw, binary.LittleEndian, int32(len(buf))); err != nil {
		return
	}
	if err = binary.Write(raw, binary.LittleEndian, buf); err != nil {
		return
	}
	b = raw.Bytes()
	return
}

// udp connection setting
func SetUdpSession(sess *kcp.UDPSession) {
	sess.SetStreamMode(true)
	sess.SetWindowSize(1024, 1024)
	sess.SetReadBuffer(64 * 1024)
	sess.SetWriteBuffer(64 * 1024)
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetMtu(1600)
	sess.SetACKNoDelay(true)
	sess.SetWriteDelay(false)
}

// conn1 mux conn
func CopyWaitGroup(conn1, conn2 net.Conn, crypt bool, snappy bool, rate *rate.Rate,
	flows []*file.Flow, isServer bool, proxyProtocol int, rb []byte, task *file.Tunnel) {
	connHandle := GetConn(conn1, crypt, snappy, rate, isServer)
	proxyHeader := BuildProxyProtocolHeader(conn2, proxyProtocol)
	if proxyHeader != nil {
		logs.Debug("Sending Proxy Protocol v%d header to backend: %v", proxyProtocol, proxyHeader)
		connHandle.Write(proxyHeader)
	}
	if rb != nil {
		connHandle.Write(rb)
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := goroutine.CopyConnsPool.Invoke(goroutine.NewConns(connHandle, conn2, flows, wg, task))
	wg.Wait()
	if err != nil {
		logs.Error("%v", err)
	}
}

// 构造 Proxy Protocol v1 头部
func BuildProxyProtocolV1Header(clientAddr, targetAddr *net.TCPAddr) []byte {
	var protocol, clientIP, targetIP string
	// 判断是否是 IPv4 地址
	if clientAddr.IP.To4() != nil {
		protocol = "TCP4" // IPv4
	} else {
		protocol = "TCP6" // IPv6
	}

	// 获取客户端和目标的 IP 地址
	clientIP = clientAddr.IP.String()
	targetIP = targetAddr.IP.String()

	// 构建 Proxy 协议 v1 头部
	header := "PROXY " + protocol + " " + clientIP + " " + targetIP + " " +
		strconv.Itoa(clientAddr.Port) + " " + strconv.Itoa(targetAddr.Port) + "\r\n"

	// 将字符串转换为字节数组并返回
	return []byte(header)
}

// 构造 Proxy Protocol v2 头部
func BuildProxyProtocolV2Header(clientAddr, targetAddr *net.TCPAddr) []byte {
	var header []byte
	if clientAddr.IP.To4() != nil {
		// IPv4
		header = make([]byte, 16+12) // v2 头部长度为 16 字节固定头 + 12 字节的 IPv4 地址信息
		copy(header[0:12], []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a})
		header[12] = 0x21                             // Proxy Protocol v2 的版本和命令
		header[13] = 0x11                             // 地址族和传输协议 (TCP over IPv4)
		binary.BigEndian.PutUint16(header[14:16], 12) // 地址信息长度
		copy(header[16:20], clientAddr.IP.To4())
		copy(header[20:24], targetAddr.IP.To4())
		binary.BigEndian.PutUint16(header[24:26], uint16(clientAddr.Port))
		binary.BigEndian.PutUint16(header[26:28], uint16(targetAddr.Port))
	} else {
		// IPv6
		header = make([]byte, 16+36) // v2 头部长度为 16 字节固定头 + 36 字节的 IPv6 地址信息
		copy(header[0:12], []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a})
		header[12] = 0x21                             // Proxy Protocol v2 的版本和命令
		header[13] = 0x21                             // 地址族和传输协议 (TCP over IPv6)
		binary.BigEndian.PutUint16(header[14:16], 36) // 地址信息长度
		copy(header[16:32], clientAddr.IP.To16())
		copy(header[32:48], targetAddr.IP.To16())
		binary.BigEndian.PutUint16(header[48:50], uint16(clientAddr.Port))
		binary.BigEndian.PutUint16(header[50:52], uint16(targetAddr.Port))
	}

	return header
}

// 构造 Proxy Protocol 头部
func BuildProxyProtocolHeader(c net.Conn, proxyProtocol int) []byte {
	if proxyProtocol == 0 {
		return nil
	}

	// 获取客户端和目标地址信息
	clientAddr := c.RemoteAddr().(*net.TCPAddr)
	targetAddr := c.LocalAddr().(*net.TCPAddr)

	if proxyProtocol == 2 {
		return BuildProxyProtocolV2Header(clientAddr, targetAddr)
	}
	if proxyProtocol == 1 {
		return BuildProxyProtocolV1Header(clientAddr, targetAddr)
	}
	return nil
}

func BuildProxyProtocolHeaderByAddr(clientAddr, targetAddr *net.TCPAddr, proxyProtocol int) []byte {
	if proxyProtocol == 0 {
		return nil
	}

	if proxyProtocol == 2 {
		return BuildProxyProtocolV2Header(clientAddr, targetAddr)
	}
	if proxyProtocol == 1 {
		return BuildProxyProtocolV1Header(clientAddr, targetAddr)
	}
	return nil
}

// get crypt or snappy conn
func GetConn(conn net.Conn, cpt, snappy bool, rt *rate.Rate, isServer bool) io.ReadWriteCloser {
	if cpt {
		if isServer {
			return rate.NewRateConn(crypt.NewTlsServerConn(conn), rt)
		}
		return rate.NewRateConn(crypt.NewTlsClientConn(conn), rt)
	} else if snappy {
		return rate.NewRateConn(NewSnappyConn(conn), rt)
	}
	return rate.NewRateConn(conn, rt)
}

type LenConn struct {
	conn io.Writer
	Len  int
}

func NewLenConn(conn io.Writer) *LenConn {
	return &LenConn{conn: conn}
}

func (c *LenConn) Write(p []byte) (n int, err error) {
	n, err = c.conn.Write(p)
	c.Len += n
	return
}

type RWConn struct {
	io.ReadWriteCloser
	FakeAddr net.Addr
}

func NewRWConn(conn io.ReadWriteCloser) *RWConn {
	return &RWConn{
		ReadWriteCloser: conn,
		FakeAddr:        LocalTCPAddr,
	}
}

func (c *RWConn) LocalAddr() net.Addr                { return c.FakeAddr }
func (c *RWConn) RemoteAddr() net.Addr               { return c.FakeAddr }
func (c *RWConn) SetDeadline(t time.Time) error      { return nil }
func (c *RWConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *RWConn) SetWriteDeadline(t time.Time) error { return nil }

type FlowConn struct {
	*RWConn
	taskFlow   *file.Flow
	clientFlow *file.Flow
}

func NewFlowConn(conn io.ReadWriteCloser, task, client *file.Flow) *FlowConn {
	return &FlowConn{
		RWConn:     NewRWConn(conn),
		taskFlow:   task,
		clientFlow: client,
	}
}

func checkFlowLimits(f *file.Flow, label string, now time.Time) error {
	if f.FlowLimit > 0 && (f.InletFlow+f.ExportFlow) > (f.FlowLimit<<20) {
		return fmt.Errorf("%s: flow limit exceeded", label)
	}
	if !f.TimeLimit.IsZero() && f.TimeLimit.Before(now) {
		return fmt.Errorf("%s: time limit exceeded", label)
	}
	return nil
}

func (c *FlowConn) Read(p []byte) (int, error) {
	n, err := c.RWConn.Read(p)
	n64 := int64(n)
	c.taskFlow.Add(0, n64)
	c.clientFlow.Add(n64, n64)
	now := time.Now()
	if err := checkFlowLimits(c.taskFlow, "Task", now); err != nil {
		return n, err
	}
	if err := checkFlowLimits(c.clientFlow, "Client", now); err != nil {
		return n, err
	}
	return n, err
}

func (c *FlowConn) Write(p []byte) (int, error) {
	n, err := c.RWConn.Write(p)
	n64 := int64(n)
	c.taskFlow.Add(n64, 0)
	c.clientFlow.Add(n64, n64)
	now := time.Now()
	if err := checkFlowLimits(c.taskFlow, "Task", now); err != nil {
		return n, err
	}
	if err := checkFlowLimits(c.clientFlow, "Client", now); err != nil {
		return n, err
	}
	return n, err
}
