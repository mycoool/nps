package proxy

import (
	"errors"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/beego/beego"
	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/conn"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/logs"
)

type Service interface {
	Start() error
	Close() error
}

type NetBridge interface {
	SendLinkInfo(clientId int, link *conn.Link, t *file.Tunnel) (target net.Conn, err error)
}

// BaseServer struct
type BaseServer struct {
	id              int
	bridge          NetBridge
	task            *file.Tunnel
	errorContent    []byte
	allowLocalProxy bool
	sync.Mutex
}

func NewBaseServer(bridge NetBridge, task *file.Tunnel) *BaseServer {
	allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy")
	return &BaseServer{
		bridge:          bridge,
		task:            task,
		errorContent:    nil,
		allowLocalProxy: allowLocalProxy,
		Mutex:           sync.Mutex{},
	}
}

// add the flow
func (s *BaseServer) FlowAdd(in, out int64) {
	s.Lock()
	defer s.Unlock()
	s.task.Flow.ExportFlow += out
	s.task.Flow.InletFlow += in
}

// change the flow
func (s *BaseServer) FlowAddHost(host *file.Host, in, out int64) {
	s.Lock()
	defer s.Unlock()
	host.Flow.ExportFlow += out
	host.Flow.InletFlow += in
}

// write fail bytes to the connection
func (s *BaseServer) writeConnFail(c net.Conn) {
	c.Write([]byte(common.ConnectionFailBytes))
	c.Write(s.errorContent)
}

// auth check
func (s *BaseServer) auth(r *http.Request, c *conn.Conn, u, p string, multiAccount, userAuth *file.MultiAccount) error {
	if !common.CheckAuth(r, u, p, file.GetAccountMap(multiAccount), file.GetAccountMap(userAuth)) {
		if c != nil {
			c.Write([]byte(common.UnauthorizedBytes))
			c.Close()
		}
		return errors.New("401 Unauthorized")
	}
	return nil
}

// check flow limit of the client ,and decrease the allow num of client
func (s *BaseServer) CheckFlowAndConnNum(client *file.Client) error {
	if !client.Flow.TimeLimit.IsZero() && client.Flow.TimeLimit.Before(time.Now()) {
		return errors.New("Service access expired.")
	}
	if client.Flow.FlowLimit > 0 && (client.Flow.FlowLimit<<20) < (client.Flow.ExportFlow+client.Flow.InletFlow) {
		return errors.New("Traffic limit exceeded.")
	}
	if !client.GetConn() {
		return errors.New("Connection limit exceeded.")
	}
	return nil
}

func in(target string, str_array []string) bool {
	sort.Strings(str_array)
	index := sort.SearchStrings(str_array, target)
	if index < len(str_array) && str_array[index] == target {
		return true
	}
	return false
}

func (s *BaseServer) DealClient(c *conn.Conn, client *file.Client, addr string,
	rb []byte, tp string, f func(), flows []*file.Flow, proxyProtocol int, localProxy bool, task *file.Tunnel) error {

	if IsGlobalBlackIp(c.RemoteAddr().String()) || common.IsBlackIp(c.RemoteAddr().String(), client.VerifyKey, client.BlackIpList) {
		c.Close()
		return nil
	}

	link := conn.NewLink(tp, addr, client.Cnf.Crypt, client.Cnf.Compress, c.Conn.RemoteAddr().String(), s.allowLocalProxy && localProxy)
	target, err := s.bridge.SendLinkInfo(client.Id, link, s.task)
	if err != nil {
		logs.Warn("get connection from client id %d  error %v", client.Id, err)
		c.Close()
		return err
	}

	if f != nil {
		f()
	}

	conn.CopyWaitGroup(target, c.Conn, link.Crypt, link.Compress, client.Rate, flows, true, proxyProtocol, rb, task)
	return nil
}

func IsGlobalBlackIp(ipPort string) bool {
	global := file.GetDb().GetGlobal()
	if global != nil {
		ip := common.GetIpByAddr(ipPort)
		if in(ip, global.BlackIpList) {
			logs.Error("IP address [%s] is in the global blacklist", ip)
			return true
		}
	}

	return false
}
