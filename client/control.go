// Package client 提供nps客户端的核心功能
// 包括与服务器的连接建立、认证、任务配置同步、P2P管理等
package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/config"
	"github.com/mycoool/nps/lib/conn"
	"github.com/mycoool/nps/lib/crypt"
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/lib/version"
	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/net/proxy"
)

const MaxPad = 64 // 最大填充字节数，用于混淆

var (
	// Ver 客户端核心版本索引，用于协议协商
	Ver = version.GetLatestIndex()
	// SkipTLSVerify 是否跳过TLS证书验证
	// true: 不验证服务器证书（不安全）
	// false: 验证服务器证书（推荐）
	SkipTLSVerify = false
	// DisableP2P 是否禁用P2P功能
	DisableP2P = false
	// AutoReconnect 是否自动重连
	// true: 连接断开后自动重连
	// false: 连接断开后退出
	AutoReconnect = true
	// P2PMode P2P连接模式，默认使用QUIC协议
	P2PMode = common.CONN_QUIC
)

var (
	// TlsCfg TLS配置，用于客户端连接
	TlsCfg = &tls.Config{
		InsecureSkipVerify: true,                      // 跳过证书验证
		ServerName:         crypt.GetFakeDomainName(), // 使用伪造的域名
		NextProtos:         []string{"h3"},            // 支持HTTP/3协议
	}
	// QuicConfig QUIC协议配置
	QuicConfig = &quic.Config{
		KeepAlivePeriod:    10 * time.Second, // 保持活跃间隔
		MaxIdleTimeout:     30 * time.Second, // 最大空闲超时
		MaxIncomingStreams: 100000,           // 最大并发流数
	}
)

// init 包初始化函数
// 1. 设置随机数种子
// 2. 初始化TLS加密模块
func init() {
	rand.Seed(time.Now().UnixNano())
	crypt.InitTls(tls.Certificate{})
}

// GetTaskStatus 获取客户端在服务器上的任务状态
// 连接到服务器并查询当前激活的隧道和主机列表
//
// 参数:
//
//	server: 服务器地址（格式：host:port 或 host:port/path）
//	vKey: 客户端验证密钥
//	tp: 连接类型（tcp、tls、ws、wss、quic、kcp）
//	proxyUrl: 代理URL（可选，如：socks5://127.0.0.1:1080）
func GetTaskStatus(server string, vKey string, tp string, proxyUrl string) {
	c, uuid, err := NewConn(tp, vKey, server, proxyUrl)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	err = SendType(c, common.WORK_CONFIG, uuid)
	if err != nil {
		log.Fatalf("Failed to send type: %v", err)
	}
	if _, err := c.BufferWrite([]byte(common.WORK_STATUS)); err != nil {
		log.Fatalf("Failed to write WORK_STATUS: %v", err)
	}
	if _, err := c.Write([]byte(crypt.Blake2b(vKey))); err != nil {
		log.Fatalf("Failed to write auth key: %v", err)
	}
	var isPub bool
	_ = binary.Read(c, binary.LittleEndian, &isPub)
	length, err := c.GetLen()
	if err != nil {
		log.Fatalf("Failed to read length: %v", err)
	}
	data, err := c.GetShortContent(length)
	if err != nil {
		log.Fatalf("Failed to read content: %v", err)
	}
	parts := strings.Split(string(data), common.CONN_DATA_SEQ)
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	log.Printf("===== Active Tunnels/Hosts =====")
	log.Printf("Total active: %d", len(parts))
	for i, name := range parts {
		display := name
		if display == "" {
			display = "(no remark)"
		}
		log.Printf("  %d. %s", i+1, display)
	}
	os.Exit(0)
}

// RegisterLocalIp 注册本地IP到服务器
// 在服务器上注册一个公网IP，有效期由hour参数指定
// 用于客户端在本地网络中获取临时公网访问能力
//
// 参数:
//
//	server: 服务器地址
//	vKey: 客户端验证密钥
//	tp: 连接类型
//	proxyUrl: 代理URL（可选）
//	hour: 有效期（小时）
func RegisterLocalIp(server string, vKey string, tp string, proxyUrl string, hour int) {
	c, uuid, err := NewConn(tp, vKey, server, proxyUrl)
	if err != nil {
		log.Fatalln(err)
	}
	//defer c.Close()
	err = SendType(c, common.WORK_REGISTER, uuid)
	if err != nil {
		log.Fatalln(err)
	}
	if err := binary.Write(c, binary.LittleEndian, int32(hour)); err != nil {
		log.Fatalln(err)
	}
	log.Printf("Successful ip registration for local public network, the validity period is %d hours.", hour)
	os.Exit(0)
}

var errAdd = errors.New("the server returned an error, which port or host may have been occupied or not allowed to open")

// StartFromFile 从配置文件启动客户端
// 这是客户端的主启动函数，会：
// 1. 加载并解析配置文件
// 2. 设置自定义DNS服务器
// 3. 同步NTP时间
// 4. 如果配置了LocalServer，则启动P2P本地服务器
// 5. 否则连接到服务器，同步配置，启动反向代理客户端
//
// 参数:
//
//	pCtx: 父上下文，用于取消操作
//	pCancel: 取消函数
//	path: 配置文件路径
func StartFromFile(pCtx context.Context, pCancel context.CancelFunc, path string) {
	cnf, err := config.NewConfig(path)
	if err != nil || cnf.CommonConfig == nil {
		logs.Error("Config file %s loading error %v", path, err)
		os.Exit(0)
	}
	logs.Info("Loading configuration file %s successfully", path)

	common.SetCustomDNS(cnf.CommonConfig.DnsServer)

	logs.Info("the version of client is %s, the core version of client is %s", version.VERSION, version.GetLatest())

	common.SetNtpServer(cnf.CommonConfig.NtpServer)
	if cnf.CommonConfig.NtpInterval > 0 {
		common.SetNtpInterval(time.Duration(cnf.CommonConfig.NtpInterval) * time.Minute)
	}
	common.SyncTime()

	var uuid string

	first := true
	for {
		select {
		case <-pCtx.Done():
			return
		default:
		}
		if !first && (!cnf.CommonConfig.AutoReconnection || !AutoReconnect) {
			pCancel()
			os.Exit(1)
			return
		}
		if !first {
			logs.Info("Reconnecting...")
			time.Sleep(time.Second * 5)
		}
		first = false

		if cnf.CommonConfig.TlsEnable {
			cnf.CommonConfig.Tp = "tls"
		}

		if len(cnf.LocalServer) > 0 {
			p2pm := NewP2PManager(pCtx, pCancel, cnf.CommonConfig)
			//create local server secret or p2p
			for _, v := range cnf.LocalServer {
				go func(lv *config.LocalServer) {
					if err := p2pm.StartLocalServer(lv); err != nil {
						logs.Error("StartLocalServer error: %v", err)
					}
				}(v)
			}
			return
		}

		c, cid, err := NewConn(cnf.CommonConfig.Tp, cnf.CommonConfig.VKey, cnf.CommonConfig.Server, cnf.CommonConfig.ProxyUrl)
		if err != nil {
			logs.Error("Failed to connect: %v", err)
			continue
		}
		if uuid == "" {
			uuid = cid
		}
		err = SendType(c, common.WORK_CONFIG, uuid)
		if err != nil {
			logs.Error("Failed to send type: %v", err)
			_ = c.Close()
			continue
		}

		var isPub bool
		_ = binary.Read(c, binary.LittleEndian, &isPub)

		// get tmp password
		var b []byte
		vkey := cnf.CommonConfig.VKey
		if isPub {
			// send global configuration to server and get status of config setting
			if _, err := c.SendInfo(cnf.CommonConfig.Client, common.NEW_CONF); err != nil {
				logs.Error("%v", err)
				_ = c.Close()
				continue
			}
			if !c.GetAddStatus() {
				logs.Error("the web_user may have been occupied!")
				_ = c.Close()
				continue
			}

			if b, err = c.GetShortContent(16); err != nil {
				logs.Error("%v", err)
				_ = c.Close()
				continue
			}
			vkey = string(b)
		}

		//if err := ioutil.WriteFile(filepath.Join(common.GetTmpPath(), "npc_vkey.txt"), []byte(vkey), 0600); err != nil {
		//	logs.Debug("Failed to write vkey file: %v", err)
		//	c.Close()
		//	continue
		//}

		//send hosts to server
		for _, v := range cnf.Hosts {
			if _, err := c.SendInfo(v, common.NEW_HOST); err != nil {
				logs.Error("%v", err)
				continue
			}
			if !c.GetAddStatus() {
				logs.Error("%v %s", errAdd, v.Host)
				continue
			}
		}

		ctx, cancel := context.WithCancel(pCtx)
		fsm := NewFileServerManager(ctx)

		//send  task to server
		for _, v := range cnf.Tasks {
			if _, err := c.SendInfo(v, common.NEW_TASK); err != nil {
				logs.Error("%v", err)
				continue
			}
			if !c.GetAddStatus() {
				logs.Error("%v %s %s", errAdd, v.Ports, v.Remark)
				continue
			}
			if v.Mode == "file" {
				//start local file server
				go fsm.StartFileServer(v, vkey)
			}
		}
		_ = c.Close()
		if cnf.CommonConfig.Client.WebUserName == "" || cnf.CommonConfig.Client.WebPassword == "" {
			logs.Info("web access login username:user password:%s", vkey)
		} else {
			logs.Info("web access login username:%s password:%s", cnf.CommonConfig.Client.WebUserName, cnf.CommonConfig.Client.WebPassword)
		}

		NewRPClient(cnf.CommonConfig.Server, vkey, cnf.CommonConfig.Tp, cnf.CommonConfig.ProxyUrl, uuid, cnf, cnf.CommonConfig.DisconnectTime, fsm).Start(ctx)
		fsm.CloseAll()
		cancel()
	}
}

// VerifyState 验证TLS连接状态和证书
// 计算服务器证书的SHA256指纹，并验证证书有效性
//
// 参数:
//
//	state: TLS连接状态
//	host: 服务器主机名（用于SNI验证）
//
// 返回:
//
//	[]byte: 证书指纹（SHA256）
//	bool: 证书是否验证成功
func VerifyState(state tls.ConnectionState, host string) (fingerprint []byte, verified bool) {
	if len(state.PeerCertificates) == 0 {
		return nil, false
	}
	leaf := state.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		inter.AddCert(cert)
	}
	roots, _ := x509.SystemCertPool()
	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
	}
	if _, err := leaf.Verify(opts); err != nil {
		verified = false
	} else {
		verified = true
	}
	sum := sha256.Sum256(leaf.Raw)
	return sum[:], verified
}

// VerifyTLS 验证TLS连接的证书
// 对网络连接执行TLS握手并验证证书
//
// 参数:
//
//	connection: 网络连接（支持*conn.TlsConn和*tls.Conn）
//	host: 服务器主机名
//
// 返回:
//
//	[]byte: 证书指纹
//	bool: 证书是否验证成功
func VerifyTLS(connection net.Conn, host string) (fingerprint []byte, verified bool) {
	var tlsConn *tls.Conn
	if tc, ok := connection.(*conn.TlsConn); ok {
		tlsConn = tc.Conn
	} else if std, ok := connection.(*tls.Conn); ok {
		tlsConn = std
	} else {
		return nil, false
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, false
	}
	return VerifyState(tlsConn.ConnectionState(), host)
}

// EnsurePort 确保服务器地址包含端口号
// 如果地址中缺少端口，则根据连接类型添加默认端口
//
// 参数:
//
//	server: 服务器地址（可能不含端口）
//	tp: 连接类型（tcp、tls等）
//
// 返回:
//
//	string: 包含端口的完整地址
func EnsurePort(server string, tp string) string {
	_, port, err := net.SplitHostPort(server)
	if err == nil && port != "" {
		return server
	}
	if p, ok := common.DefaultPort[tp]; ok {
		return net.JoinHostPort(server, p)
	}
	return server
}

// NewConn 创建与服务器的连接并进行验证
// 支持多种连接类型：tcp、tls、ws、wss、quic、kcp
// 连接后会进行版本协商和身份验证
//
// 认证流程（版本>=0.27.0）：
// 1. 发送测试报文CONN_TEST
// 2. 发送客户端支持的最小版本
// 3. 发送客户端当前版本（带随机填充）
// 4. 发送时间戳和vkey的Blake2b哈希
// 5. 发送客户端信息（IP、连接类型等，加密）
// 6. 发送随机数据（1000字节）
// 7. 计算并发送HMAC签名
// 8. 接收服务器响应验证版本和证书
//
// 参数:
//
//	tp: 连接类型（tcp、tls、ws、wss、quic、kcp）
//	vkey: 客户端验证密钥
//	server: 服务器地址（格式：host:port 或 host:port/path）
//	proxyUrl: 代理URL（可选）
//
// 返回:
//
//	*conn.Conn: 连接对象
//	string: UUID（连接唯一标识符）
//	error: 错误信息
func NewConn(tp string, vkey string, server string, proxyUrl string) (*conn.Conn, string, error) {
	//logs.Debug("NewConn: %s %s %s %s %s", tp, vkey, server, connType, proxyUrl)
	var err error
	var connection net.Conn
	var sess *kcp.UDPSession
	var path string
	var isTls = false
	var tlsVerify = false
	var tlsFp []byte

	timeout := time.Second * 10
	alpn := "nps"
	server, path = common.SplitServerAndPath(server)
	if path == "" {
		path = "/ws"
	} else {
		alpn = strings.TrimSpace(strings.TrimPrefix(path, "/"))
	}
	addr, host, sni := common.SplitAddrAndHost(server)
	server = EnsurePort(addr, tp)

	if HasFailed {
		if s, e := common.GetFastAddr(server, tp); e == nil {
			server = s
			//logs.Debug("Fast Server: %s", server)
		} else {
			logs.Debug("Server: %s Path: %s Error: %v", server, path, e)
		}
	}

	switch tp {
	case "tcp":
		connection, err = GetProxyConn(proxyUrl, server, timeout)
	case "tls":
		isTls = true
		conf := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         sni,
		}
		rawConn, err := GetProxyConn(proxyUrl, server, timeout)
		if err != nil {
			return nil, "", err
		}
		connection, err = conn.NewTlsConn(rawConn, timeout, conf)
		if err != nil {
			_ = rawConn.Close()
			return nil, "", err
		}
		tlsFp, tlsVerify = VerifyTLS(connection, sni)
	case "ws":
		rawConn, err := GetProxyConn(proxyUrl, server, timeout)
		if err != nil {
			return nil, "", err
		}
		urlStr := "ws://" + server + path
		//logs.Debug("URL: %s", urlStr)
		wsConn, _, err := conn.DialWS(rawConn, urlStr, host, timeout)
		if err != nil {
			_ = rawConn.Close()
			return nil, "", err
		}
		connection = conn.NewWsConn(wsConn)
	case "wss":
		isTls = true
		urlStr := "wss://" + server + path
		//logs.Debug("URL: %s Host: %s SNI: %s", urlStr, host, sni)
		rawConn, err := GetProxyConn(proxyUrl, server, timeout)
		if err != nil {
			return nil, "", err
		}
		wsConn, _, err := conn.DialWSS(rawConn, urlStr, host, sni, timeout)
		if err != nil {
			_ = rawConn.Close()
			return nil, "", err
		}
		if underlying := wsConn.NetConn(); underlying != nil {
			tlsFp, tlsVerify = VerifyTLS(underlying, sni)
		}
		connection = conn.NewWsConn(wsConn)
	case "quic":
		isTls = true
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         sni,
			NextProtos:         []string{alpn},
		}
		ctx := context.Background()
		sess, err := quic.DialAddr(ctx, server, tlsCfg, QuicConfig)
		if err != nil {
			return nil, "", fmt.Errorf("quic dial error: %w", err)
		}
		state := sess.ConnectionState().TLS
		tlsFp, tlsVerify = VerifyState(state, sni)
		stream, err := sess.OpenStreamSync(ctx)
		if err != nil {
			_ = sess.CloseWithError(0, "")
			return nil, "", fmt.Errorf("quic open stream error: %w", err)
		}
		connection = conn.NewQuicAutoCloseConn(stream, sess)
	default:
		sess, err = kcp.DialWithOptions(server, nil, 10, 3)
		if err == nil {
			conn.SetUdpSession(sess)
			connection = sess
		}
	}

	if connection == nil {
		return nil, "", fmt.Errorf("NewConn: unexpected nil connection for tp=%q server=%q", tp, server)
	}

	if err != nil {
		_ = connection.Close()
		return nil, "", err
	}

	//logs.Debug("SetDeadline")
	_ = connection.SetDeadline(time.Now().Add(timeout))
	defer func() {
		_ = connection.SetDeadline(time.Time{})
	}()

	c := conn.NewConn(connection)
	if _, err := c.BufferWrite([]byte(common.CONN_TEST)); err != nil {
		_ = c.Close()
		return nil, "", err
	}
	minVerBytes := []byte(version.GetVersion(Ver))
	if err := c.WriteLenContent(minVerBytes); err != nil {
		_ = c.Close()
		return nil, "", err
	}
	vs := []byte(version.VERSION)
	padLen := rand.Intn(MaxPad)
	if padLen > 0 {
		vs = append(vs, make([]byte, padLen)...)
	}
	if err := c.WriteLenContent(vs); err != nil {
		_ = c.Close()
		return nil, "", err
	}
	var uuid string
	if Ver == 0 {
		// 0.26.0
		b, err := c.GetShortContent(32)
		if err != nil {
			logs.Error("%v", err)
			_ = c.Close()
			return nil, "", err
		}
		if crypt.Md5(version.GetVersion(Ver)) != string(b) {
			logs.Warn("The client does not match the server version. The current core version of the client is %s", version.GetVersion(Ver))
			//_ = c.Close()
			//return nil, err
		}
		if _, err := c.BufferWrite([]byte(crypt.Md5(vkey))); err != nil {
			_ = c.Close()
			return nil, "", err
		}
		if s, err := c.ReadFlag(); err != nil {
			_ = c.Close()
			return nil, "", err
		} else if s == common.VERIFY_EER {
			_ = c.Close()
			return nil, "", fmt.Errorf("validation key %s incorrect", vkey)
		}
	} else {
		// 0.27.0
		ts := common.TimeNow().Unix() - int64(rand.Intn(6))
		if _, err := c.BufferWrite(common.TimestampToBytes(ts)); err != nil {
			_ = c.Close()
			return nil, "", err
		}
		if _, err := c.BufferWrite([]byte(crypt.Blake2b(vkey))); err != nil {
			_ = c.Close()
			return nil, "", err
		}
		var infoBuf []byte
		if Ver < 3 {
			// 0.27.0 0.28.0
			var err error
			infoBuf, err = crypt.EncryptBytes(common.EncodeIP(common.GetOutboundIP()), vkey)
			if err != nil {
				_ = c.Close()
				return nil, "", err
			}
		} else {
			// 0.29.0
			ipPart := common.EncodeIP(common.GetOutboundIP()) // 17bit
			tpBytes := []byte(tp)
			tpLen := len(tpBytes)
			if tpLen > 32 {
				_ = c.Close()
				return nil, "", fmt.Errorf("tp too long: %d bytes (max %d)", tpLen, 32)
			}
			length := byte(tpLen)
			// IP(17 bit) + len(1 bit) + tpBytes
			buf := make([]byte, 0, len(ipPart)+1+len(tpBytes))
			buf = append(buf, ipPart...)
			buf = append(buf, length)
			buf = append(buf, tpBytes...)
			var err error
			infoBuf, err = crypt.EncryptBytes(buf, vkey)
			if err != nil {
				_ = c.Close()
				return nil, "", err
			}
		}
		if err := c.WriteLenContent(infoBuf); err != nil {
			_ = c.Close()
			return nil, "", err
		}
		randBuf, err := common.RandomBytes(1000)
		if err != nil {
			_ = c.Close()
			return nil, "", err
		}
		if err := c.WriteLenContent(randBuf); err != nil {
			_ = c.Close()
			return nil, "", err
		}
		hmacBuf := crypt.ComputeHMAC(vkey, ts, minVerBytes, vs, infoBuf, randBuf)
		if _, err := c.BufferWrite(hmacBuf); err != nil {
			_ = c.Close()
			return nil, "", err
		}
		b, err := c.GetShortContent(32)
		if err != nil {
			logs.Error("error reading server response: %v", err)
			_ = c.Close()
			return nil, "", fmt.Errorf("Validation key %s incorrect", vkey)
		}
		if !bytes.Equal(b, crypt.ComputeHMAC(vkey, ts, hmacBuf, []byte(version.GetVersion(Ver)))) {
			logs.Warn("The client does not match the server version. The current core version of the client is %s", version.GetVersion(Ver))
			_ = c.Close()
			return nil, "", err
		}
		if Ver > 1 {
			fpBuf, err := c.GetShortLenContent()
			if err != nil {
				_ = c.Close()
				return nil, "", err
			}
			fpDec, err := crypt.DecryptBytes(fpBuf, vkey)
			if err != nil {
				_ = c.Close()
				return nil, "", err
			}
			if !SkipTLSVerify && isTls && !tlsVerify && !bytes.Equal(fpDec, tlsFp) {
				logs.Warn("Certificate verification failed. To skip verification, please set -skip_verify=true")
				_ = c.Close()
				return nil, "", errors.New("validation cert incorrect")
			}
			crypt.AddTrustedCert(vkey, fpDec)
			if Ver > 3 {
				// v0.30.0
				if Ver > 5 {
					// v0.32.0
					uuidBuf, err := c.GetShortLenContent()
					if err != nil {
						_ = c.Close()
						return nil, "", err
					}
					uuid = string(uuidBuf)
				}
				_, err := c.GetShortLenContent()
				if err != nil {
					_ = c.Close()
					return nil, "", err
				}
			}
		}
	}
	//_, err = SendType(c, connType, uuid)
	return c, uuid, err
}

// SendType 发送连接类型和UUID到服务器
// 在发送连接请求前，需要告知服务器工作类型和连接标识
//
// 参数:
//
//	c: 连接对象
//	connType: 连接类型（WORK_CONFIG、WORK_REGISTER等）
//	uuid: 连接的唯一标识符
//
// 返回:
//
//	error: 错误信息
func SendType(c *conn.Conn, connType, uuid string) error {
	if _, err := c.BufferWrite([]byte(connType)); err != nil {
		_ = c.Close()
		return err
	}
	if Ver > 3 {
		// v0.30.0
		if Ver > 5 {
			// v0.32.0
			if err := c.WriteLenContent([]byte(uuid)); err != nil {
				_ = c.Close()
				return err
			}
		}
		randByte, err := common.RandomBytes(1000)
		if err != nil {
			_ = c.Close()
			return err
		}
		if err := c.WriteLenContent(randByte); err != nil {
			_ = c.Close()
			return err
		}
	}
	if err := c.FlushBuf(); err != nil {
		_ = c.Close()
		return err
	}
	c.SetAlive()
	return nil
}

// GetProxyConn 通过代理建立TCP连接
// 支持SOCKS5和HTTP代理
//
// 参数:
//
//	proxyUrl: 代理URL（如：socks5://127.0.0.1:1080）
//	server: 目标服务器地址
//	timeout: 连接超时时间
//
// 返回:
//
//	net.Conn: 网络连接
//	error: 错误信息
func GetProxyConn(proxyUrl, server string, timeout time.Duration) (rawConn net.Conn, err error) {
	if proxyUrl != "" {
		u, er := url.Parse(proxyUrl)
		if er != nil {
			return nil, er
		}
		switch u.Scheme {
		case "socks5":
			dialer := &net.Dialer{Timeout: timeout}
			n, er := proxy.FromURL(u, dialer)
			if er != nil {
				return nil, er
			}
			rawConn, err = n.Dial("tcp", server)
		default:
			rawConn, err = NewHttpProxyConn(u, server, timeout)
		}
	} else {
		dialer := &net.Dialer{Timeout: timeout}
		n := proxy.FromEnvironmentUsing(dialer)
		rawConn, err = n.Dial("tcp", server)
	}
	if err != nil {
		return nil, err
	}
	return rawConn, nil
}

// NewHttpProxyConn 通过HTTP代理建立连接
// 使用HTTP CONNECT方法建立到目标服务器的隧道连接
//
// 参数:
//
//	proxyURL: 代理URL
//	remoteAddr: 目标服务器地址
//	timeout: 连接超时时间
//
// 返回:
//
//	net.Conn: 代理连接
//	error: 错误信息
func NewHttpProxyConn(proxyURL *url.URL, remoteAddr string, timeout time.Duration) (net.Conn, error) {
	proxyConn, err := net.DialTimeout("tcp", proxyURL.Host, timeout)
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: remoteAddr},
		Host:   remoteAddr,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		req.SetBasicAuth(username, password)
	}
	if err := req.Write(proxyConn); err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
	if err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = proxyConn.Close()
		return nil, errors.New("proxy CONNECT failed: " + resp.Status)
	}
	return proxyConn, nil
}
