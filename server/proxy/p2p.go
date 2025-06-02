package proxy

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/logs"
)

type P2PServer struct {
	BaseServer
	p2pPort  int
	sessions sync.Map // key string → *session
	listener *net.UDPConn
}

type session struct {
	mu            sync.Mutex
	visitorAddr   *net.UDPAddr
	providerAddr  *net.UDPAddr
	visitorLocal  string
	providerLocal string
	timer         *time.Timer
	once          sync.Once
}

func NewP2PServer(p2pPort int) *P2PServer {
	return &P2PServer{p2pPort: p2pPort}
}

func (s *P2PServer) Start() error {
	logs.Info("start p2p server port %d", s.p2pPort)
	var err error
	s.listener, err = net.ListenUDP("udp", &net.UDPAddr{net.ParseIP("0.0.0.0"), s.p2pPort, ""})
	if err != nil {
		return err
	}
	for {
		buf := common.BufPoolUdp.Get().([]byte)
		n, addr, err := s.listener.ReadFromUDP(buf)
		if err != nil {
			common.BufPoolUdp.Put(buf)
			if strings.Contains(err.Error(), "use of closed network connection") {
				break
			}
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		common.BufPoolUdp.Put(buf)
		go s.handleP2P(addr, data)
	}
	return nil
}

func (s *P2PServer) handleP2P(addr *net.UDPAddr, data []byte) {
	logs.Trace("P2P receive data %s from %v", data, addr)
	chunks := bytes.Split(data, []byte(common.CONN_DATA_SEQ))
	if len(chunks) < 2 {
		return
	}
	key := string(chunks[0])
	role := string(chunks[1])
	var localStr string
	if len(chunks) >= 3 {
		localStr = string(chunks[2])
	}

	if t := file.GetDb().GetTaskByMd5Password(key); t == nil {
		logs.Error("p2p error, failed to match the key successfully")
		return
	}

	v, _ := s.sessions.LoadOrStore(key, &session{})
	sess := v.(*session)

	sess.mu.Lock()
	defer sess.mu.Unlock()
	logs.Trace("P2P %s [%s] from %v (local %q)", role, key, addr, localStr)

	switch role {
	case common.WORK_P2P_VISITOR:
		sess.visitorAddr = addr
		sess.visitorLocal = localStr
	case common.WORK_P2P_PROVIDER:
		sess.providerAddr = addr
		sess.providerLocal = localStr
	default:
		sess.providerAddr = addr
		sess.providerLocal = localStr
	}

	if sess.visitorAddr != nil && sess.providerAddr != nil {
		var toVisitor []byte
		var toProvider []byte
		if sess.visitorLocal != "" && sess.providerLocal != "" {
			toVisitor = common.GetWriteStr(sess.providerAddr.String(), sess.providerLocal)
			toProvider = common.GetWriteStr(sess.visitorAddr.String(), sess.visitorLocal)
		} else {
			toVisitor = []byte(sess.providerAddr.String())
			toProvider = []byte(sess.visitorAddr.String())
		}
		for i := 0; i < 3; i++ {
			if _, err := s.listener.WriteTo(toVisitor, sess.visitorAddr); err != nil {
				logs.Warn("failed to send to visitor %v: %v", sess.visitorAddr, err)
			}
			if _, err := s.listener.WriteTo(toProvider, sess.providerAddr); err != nil {
				logs.Warn("failed to send to provider %v: %v", sess.providerAddr, err)
			}
		}
		logs.Trace("sent P2P addresses visitor=%v (%q) provider=%v (%q)", sess.visitorAddr, sess.visitorLocal, sess.providerAddr, sess.providerLocal)
		if sess.timer != nil {
			sess.timer.Stop()
		}
		s.sessions.Delete(key)
	} else {
		sess.once.Do(func() {
			sess.timer = time.AfterFunc(20*time.Second, func() {
				s.sessions.Delete(key)
			})
		})
	}
}
