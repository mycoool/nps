package file

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mycoool/nps/lib/rate"
	"github.com/pkg/errors"
)

type Flow struct {
	ExportFlow int64     // 传出流量
	InletFlow  int64     // 传入流量
	FlowLimit  int64     // 流量限制
	TimeLimit  time.Time // 连接到期时间
	sync.RWMutex
}

func (s *Flow) Add(in, out int64) {
	s.Lock()
	s.InletFlow += int64(in)
	s.ExportFlow += int64(out)
	s.Unlock()
}

func (s *Flow) Sub(in, out int64) {
	s.Lock()
	s.InletFlow -= int64(in)
	s.ExportFlow -= int64(out)
	s.Unlock()
}

type Config struct {
	U        string // username
	P        string // password
	Compress bool
	Crypt    bool
}

type Client struct {
	Cnf             *Config
	Id              int        //id
	VerifyKey       string     //verify key
	Mode            string     //bridge mode
	Addr            string     //the ip of client
	LocalAddr       string     //the local ip of client
	Remark          string     //remark
	Status          bool       //is allowed connect
	IsConnect       bool       //is the client connect
	RateLimit       int        //rate /kb
	Flow            *Flow      //flow setting
	ExportFlow      int64      //flow out
	InletFlow       int64      //flow in
	Rate            *rate.Rate //rate limit
	NoStore         bool       //no store to file
	NoDisplay       bool       //no display on web
	MaxConn         int        //the max connection num of client allow
	NowConn         int32      //the connection num of now
	WebUserName     string     //the username of web login
	WebPassword     string     //the password of web login
	ConfigConnAllow bool       //is allowed connected by config file
	MaxTunnelNum    int
	Version         string
	BlackIpList     []string
	CreateTime      string
	LastOnlineTime  string
	sync.RWMutex
}

func NewClient(vKey string, noStore bool, noDisplay bool) *Client {
	return &Client{
		Cnf:       new(Config),
		Id:        0,
		VerifyKey: vKey,
		Addr:      "",
		Remark:    "",
		Status:    true,
		IsConnect: false,
		RateLimit: 0,
		Flow:      new(Flow),
		Rate:      nil,
		NoStore:   noStore,
		RWMutex:   sync.RWMutex{},
		NoDisplay: noDisplay,
	}
}

func (s *Client) AddConn() {
	atomic.AddInt32(&s.NowConn, 1)
}

func (s *Client) CutConn() {
	atomic.AddInt32(&s.NowConn, -1)
}

func (s *Client) GetConn() bool {
	if s.NowConn < 0 {
		s.NowConn = 0
	}
	if s.MaxConn == 0 || int(s.NowConn) < s.MaxConn {
		s.AddConn()
		return true
	}
	return false
}

func (s *Client) HasTunnel(t *Tunnel) (exist bool) {
	GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		v := value.(*Tunnel)
		if v.Client.Id == s.Id && v.Port == t.Port && t.Port != 0 {
			exist = true
			return false
		}
		return true
	})
	return
}

func (s *Client) GetTunnelNum() (num int) {
	GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		v := value.(*Tunnel)
		if v.Client.Id == s.Id {
			num++
		}
		return true
	})

	GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
		v := value.(*Host)
		if v.Client.Id == s.Id {
			num++
		}
		return true
	})
	return
}

func (s *Client) HasHost(h *Host) bool {
	var has bool
	GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
		v := value.(*Host)
		if v.Client.Id == s.Id && v.Host == h.Host && h.Location == v.Location {
			has = true
			return false
		}
		return true
	})
	return has
}

type Tunnel struct {
	Id           int
	Port         int
	ServerIp     string
	Mode         string
	Status       bool
	RunStatus    bool
	Client       *Client
	Ports        string
	Flow         *Flow
	Password     string
	Remark       string
	TargetAddr   string
	NoStore      bool
	IsHttp       bool
	HttpProxy    bool
	Socks5Proxy  bool
	LocalPath    string
	StripPre     string
	Target       *Target
	UserAuth     *MultiAccount
	MultiAccount *MultiAccount
	Health
	sync.RWMutex
}

type Health struct {
	HealthCheckTimeout  int
	HealthMaxFail       int
	HealthCheckInterval int
	HealthNextTime      time.Time
	HealthMap           map[string]int
	HttpHealthUrl       string
	HealthRemoveArr     []string
	HealthCheckType     string
	HealthCheckTarget   string
	sync.RWMutex
}

type Host struct {
	Id             int
	Host           string //host
	HeaderChange   string //header change
	HostChange     string //host change
	Location       string //url router
	PathRewrite    string //url rewrite
	Remark         string //remark
	Scheme         string //http https all
	HttpsJustProxy bool
	AutoSSL        bool
	CertType       string
	CertHash       string
	CertFile       string
	KeyFile        string
	NoStore        bool
	IsClose        bool
	AutoHttps      bool
	AutoCORS       bool
	Flow           *Flow
	Client         *Client
	TargetIsHttps  bool
	Target         *Target //目标
	UserAuth       *MultiAccount
	Health         `json:"-"`
	sync.RWMutex
}

type Target struct {
	nowIndex      int
	TargetStr     string
	TargetArr     []string
	LocalProxy    bool
	ProxyProtocol int // Proxy Protocol 配置：0=关闭, 1=v1, 2=v2
	sync.RWMutex
}

type MultiAccount struct {
	Content    string
	AccountMap map[string]string // multi account and pwd
}

func GetAccountMap(multiAccount *MultiAccount) map[string]string {
	var accountMap map[string]string
	if multiAccount == nil {
		accountMap = nil
	} else {
		accountMap = multiAccount.AccountMap
	}
	return accountMap
}

func (s *Target) GetRandomTarget() (string, error) {
	// 初始化 TargetArr 并过滤空行
	if s.TargetArr == nil {
		lines := strings.Split(strings.ReplaceAll(s.TargetStr, "\r\n", "\n"), "\n")
		for _, v := range lines {
			trimmed := strings.TrimSpace(v) // 去除前后空白
			if trimmed != "" {
				s.TargetArr = append(s.TargetArr, trimmed)
			}
		}
	}

	// 确保 TargetArr 中有有效内容
	if len(s.TargetArr) == 1 {
		return s.TargetArr[0], nil
	}
	if len(s.TargetArr) == 0 {
		return "", errors.New("all inward-bending targets are offline")
	}

	// 锁定并更新索引
	s.Lock()
	defer s.Unlock()
	if s.nowIndex >= len(s.TargetArr)-1 {
		s.nowIndex = -1
	}
	s.nowIndex++
	return s.TargetArr[s.nowIndex], nil
}

type Glob struct {
	BlackIpList []string
	sync.RWMutex
}
