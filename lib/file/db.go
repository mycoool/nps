// Package file 提供数据库操作和配置管理功能
// 包括客户端、任务、主机、全局配置的增删改查
package file

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/crypt"
	"github.com/mycoool/nps/lib/index"
	"github.com/mycoool/nps/lib/rate"
)

// DbUtils 数据库工具类
// 提供对JSON数据库的各种操作接口
type DbUtils struct {
	JsonDb *JsonDb // JSON数据库实例
}

var (
	// Db 数据库单例实例
	Db *DbUtils
	// once 用于确保数据库只初始化一次
	once sync.Once
	// HostIndex 主机索引，用于快速通过域名查找主机配置
	HostIndex = index.NewDomainIndex()
	// Blake2bVkeyIndex 客户端vkey的Blake2b哈希索引，用于快速查找客户端
	Blake2bVkeyIndex = index.NewStringIDIndex()
	// TaskPasswordIndex 任务密码的MD5索引，用于快速查找任务
	TaskPasswordIndex = index.NewStringIDIndex()
)

// GetDb 获取数据库单例实例
// 使用sync.Once确保只初始化一次
// 初始化时会加载所有配置文件（客户端、任务、主机、全局配置）
//
// 返回:
//
//	*DbUtils: 数据库工具实例
func GetDb() *DbUtils {
	once.Do(func() {
		jsonDb := NewJsonDb(common.GetRunPath())
		jsonDb.LoadClientFromJsonFile()
		jsonDb.LoadTaskFromJsonFile()
		jsonDb.LoadHostFromJsonFile()
		jsonDb.LoadGlobalFromJsonFile()
		Db = &DbUtils{JsonDb: jsonDb}
	})
	return Db
}

// GetMapKeys 获取sync.Map的所有key
// 支持按指定字段排序
//
// 参数:
//
//	m: sync.Map对象
//	isSort: 是否按sortKey排序
//	sortKey: 排序字段（InletFlow、ExportFlow等）
//	order: 排序方式
//
// 返回:
//
//	[]int: key列表
func GetMapKeys(m *sync.Map, isSort bool, sortKey, order string) (keys []int) {
	if (sortKey == "InletFlow" || sortKey == "ExportFlow") && isSort {
		return sortClientByKey(m, sortKey, order)
	}
	m.Range(func(key, value interface{}) bool {
		keys = append(keys, key.(int))
		return true
	})
	sort.Ints(keys)
	return
}

// GetClientList 分页获取客户端列表
//
// 参数:
//
//	start: 起始位置（分页）
//	length: 每页数量，0表示全部
//	search: 搜索关键字（匹配ID、vkey、备注）
//	sort: 排序字段
//	order: 排序方式（asc/desc）
//	clientId: 客户端ID过滤，0表示不限制
//
// 返回:
//
//	[]*Client: 客户端列表
//	int: 总数量
func (s *DbUtils) GetClientList(start, length int, search, sort, order string, clientId int) ([]*Client, int) {
	list := make([]*Client, 0)
	var cnt int
	originLength := length
	keys := GetMapKeys(&s.JsonDb.Clients, true, sort, order)
	for _, key := range keys {
		if value, ok := s.JsonDb.Clients.Load(key); ok {
			v := value.(*Client)
			if v.NoDisplay {
				continue
			}
			if clientId != 0 && clientId != v.Id {
				continue
			}
			if search != "" && !(v.Id == common.GetIntNoErrByStr(search) || common.ContainsFold(v.VerifyKey, search) || common.ContainsFold(v.Remark, search)) {
				continue
			}
			cnt++
			if start--; start < 0 {
				if originLength == 0 {
					list = append(list, v)
				} else if length--; length >= 0 {
					list = append(list, v)
				}
			}
		}
	}
	return list, cnt
}

// GetIdByVerifyKey 根据验证密钥查找客户端ID
// 客户端连接时会发送vkey的哈希值，服务器通过此函数查找对应的客户端
//
// 参数:
//
//	vKey: 客户端vkey的哈希值
//	addr: 客户端地址
//	localAddr: 客户端本地地址
//	hashFunc: 哈希函数
//
// 返回:
//
//	int: 客户端ID
//	error: 错误信息，找不到返回错误
func (s *DbUtils) GetIdByVerifyKey(vKey, addr, localAddr string, hashFunc func(string) string) (id int, err error) {
	var exist bool
	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*Client)
		if hashFunc(v.VerifyKey) == vKey && v.Status && v.Id > 0 {
			v.Addr = common.GetIpByAddr(addr)
			v.LocalAddr = common.GetIpByAddr(localAddr)
			id = v.Id
			exist = true
			return false
		}
		return true
	})
	if exist {
		return
	}
	return 0, errors.New("not found")
}

func (s *DbUtils) GetClientIdByBlake2bVkey(vkey string) (id int, err error) {
	var exist bool
	id, exist = Blake2bVkeyIndex.Get(vkey)
	if exist {
		return
	}
	err = errors.New("can not find client")
	return
}

func (s *DbUtils) GetClientIdByMd5Vkey(vkey string) (id int, err error) {
	var exist bool
	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*Client)
		if crypt.Md5(v.VerifyKey) == vkey {
			exist = true
			id = v.Id
			return false
		}
		return true
	})
	if exist {
		return
	}
	err = errors.New("can not find client")
	return
}

// NewTask 创建新任务
// 自动生成密钥（如果需要），初始化流量对象，建立密码索引
// 将socks5和httpProxy模式转换为mixProxy模式
//
// 参数:
//
//	t: 隧道任务配置
//
// 返回:
//
//	error: 错误信息
func (s *DbUtils) NewTask(t *Tunnel) (err error) {
	//s.JsonDb.Tasks.Range(func(key, value interface{}) bool {
	//	v := value.(*Tunnel)
	//	if (v.Mode == "secret" || v.Mode == "p2p") && (t.Mode == "secret" || t.Mode == "p2p") && v.Password == t.Password {
	//		err = errors.New(fmt.Sprintf("secret mode keys %s must be unique", t.Password))
	//		return false
	//	}
	//	return true
	//})
	//if err != nil {
	//	return
	//}
	if (t.Mode == "secret" || t.Mode == "p2p") && t.Password == "" {
		t.Password = crypt.GetRandomString(16, t.Id)
	}

	t.Flow = new(Flow)

	if t.Password != "" {
		for {
			hash := crypt.Md5(t.Password)
			if idxId, ok := TaskPasswordIndex.Get(hash); !ok || idxId == t.Id {
				TaskPasswordIndex.Add(hash, t.Id)
				break
			}
			t.Password = crypt.GetRandomString(16, t.Id)
		}
	}

	switch t.Mode {
	case "socks5":
		t.Mode = "mixProxy"
		t.HttpProxy = false
		t.Socks5Proxy = true
	case "httpProxy":
		t.Mode = "mixProxy"
		t.HttpProxy = true
		t.Socks5Proxy = false
	}
	if t.TargetType != common.CONN_TCP && t.TargetType != common.CONN_UDP {
		t.TargetType = common.CONN_ALL
	}
	s.JsonDb.Tasks.Store(t.Id, t)
	s.JsonDb.StoreTasksToJsonFile()
	return
}

// UpdateTask 更新任务配置
// 处理密码更新和索引维护
//
// 参数:
//
//	t: 隧道任务配置
//
// 返回:
//
//	error: 错误信息
func (s *DbUtils) UpdateTask(t *Tunnel) error {
	if (t.Mode == "secret" || t.Mode == "p2p") && t.Password == "" {
		t.Password = crypt.GetRandomString(16, t.Id)
	}

	if v, ok := s.JsonDb.Tasks.Load(t.Id); ok {
		if oldPwd := v.(*Tunnel).Password; oldPwd != "" {
			if idxId, ok := TaskPasswordIndex.Get(crypt.Md5(oldPwd)); ok && idxId == t.Id {
				TaskPasswordIndex.Remove(crypt.Md5(oldPwd))
			}
		}
	}

	if t.Password != "" {
		for {
			hash := crypt.Md5(t.Password)
			if idxId, ok := TaskPasswordIndex.Get(hash); !ok || idxId == t.Id {
				TaskPasswordIndex.Add(hash, t.Id)
				break
			}
			t.Password = crypt.GetRandomString(16, t.Id)
		}
	}
	switch t.Mode {
	case "socks5":
		t.Mode = "mixProxy"
		t.HttpProxy = false
		t.Socks5Proxy = true
	case "httpProxy":
		t.Mode = "mixProxy"
		t.HttpProxy = true
		t.Socks5Proxy = false
	}
	if t.TargetType != common.CONN_TCP && t.TargetType != common.CONN_UDP {
		t.TargetType = common.CONN_ALL
	}
	s.JsonDb.Tasks.Store(t.Id, t)
	s.JsonDb.StoreTasksToJsonFile()
	return nil
}

// SaveGlobal 保存全局配置
//
// 参数:
//
//	t: 全局配置对象
//
// 返回:
//
//	error: 错误信息
func (s *DbUtils) SaveGlobal(t *Glob) error {
	s.JsonDb.Global = t
	s.JsonDb.StoreGlobalToJsonFile()
	return nil
}

// DelTask 删除指定ID的任务
// 同时移除密码索引
//
// 参数:
//
//	id: 任务ID
//
// 返回:
//
//	error: 错误信息
func (s *DbUtils) DelTask(id int) error {
	if v, ok := s.JsonDb.Tasks.Load(id); ok {
		t := v.(*Tunnel)
		TaskPasswordIndex.Remove(crypt.Md5(t.Password))
	}
	s.JsonDb.Tasks.Delete(id)
	s.JsonDb.StoreTasksToJsonFile()
	return nil
}

// GetTaskByMd5Password 根据密码的MD5哈希查找任务
// 用于secret模式和p2p模式的任务查找
//
// 参数:
//
//	p: 密码的MD5哈希值
//
// 返回:
//
//	*Tunnel: 任务对象，未找到返回nil
func (s *DbUtils) GetTaskByMd5Password(p string) (t *Tunnel) {
	id, ok := TaskPasswordIndex.Get(p)
	if ok {
		if v, ok := s.JsonDb.Tasks.Load(id); ok {
			t = v.(*Tunnel)
			return
		}
	}
	return
}

func (s *DbUtils) GetTaskByMd5PasswordOld(p string) (t *Tunnel) {
	s.JsonDb.Tasks.Range(func(key, value interface{}) bool {
		if crypt.Md5(value.(*Tunnel).Password) == p {
			t = value.(*Tunnel)
			return false
		}
		return true
	})
	return
}

// GetTask 根据ID获取任务
//
// 参数:
//
//	id: 任务ID
//
// 返回:
//
//	*Tunnel: 任务对象
//	error: 错误信息
func (s *DbUtils) GetTask(id int) (t *Tunnel, err error) {
	if v, ok := s.JsonDb.Tasks.Load(id); ok {
		t = v.(*Tunnel)
		return
	}
	err = errors.New("not found")
	return
}

// DelHost 删除指定ID的主机
// 同时从域名索引中移除
//
// 参数:
//
//	id: 主机ID
//
// 返回:
//
//	error: 错误信息
func (s *DbUtils) DelHost(id int) error {
	if v, ok := s.JsonDb.Hosts.Load(id); ok {
		h := v.(*Host)
		HostIndex.Remove(h.Host, id)
	}
	s.JsonDb.Hosts.Delete(id)
	s.JsonDb.StoreHostToJsonFile()
	return nil
}

// IsHostExist 检查主机是否已存在
// 比较主机名、路径、协议是否相同
//
// 参数:
//
//	h: 主机配置
//
// 返回:
//
//	bool: true表示已存在
func (s *DbUtils) IsHostExist(h *Host) bool {
	var exist bool
	if h.Location == "" {
		h.Location = "/"
	}
	s.JsonDb.Hosts.Range(func(key, value interface{}) bool {
		v := value.(*Host)
		if v.Location == "" {
			v.Location = "/"
		}
		if v.Id != h.Id && v.Host == h.Host && h.Location == v.Location && (v.Scheme == "all" || v.Scheme == h.Scheme) {
			exist = true
			return false
		}
		return true
	})
	return exist
}

// IsHostModify 检查主机配置是否已修改
// 比较关键字段是否有变化
//
// 参数:
//
//	h: 主机配置
//
// 返回:
//
//	bool: true表示有修改或主机不存在
func (s *DbUtils) IsHostModify(h *Host) bool {
	if h == nil {
		return true
	}

	existingHost, err := s.GetHostById(h.Id)
	if err != nil {
		return true
	}

	if existingHost.IsClose != h.IsClose ||
		existingHost.Host != h.Host ||
		existingHost.Location != h.Location ||
		existingHost.Scheme != h.Scheme ||
		existingHost.HttpsJustProxy != h.HttpsJustProxy ||
		existingHost.CertFile != h.CertFile ||
		existingHost.KeyFile != h.KeyFile {
		return true
	}

	return false
}

// NewHost 创建新主机
// 检查是否存在，初始化流量对象，建立域名索引
//
// 参数:
//
//	t: 主机配置
//
// 返回:
//
//	error: 错误信息
func (s *DbUtils) NewHost(t *Host) error {
	if t.Location == "" {
		t.Location = "/"
	}
	if t.Scheme != "all" && t.Scheme != "http" && t.Scheme != "https" {
		t.Scheme = "all"
	}
	if s.IsHostExist(t) {
		return errors.New("host has exist")
	}
	HostIndex.Add(t.Host, t.Id)
	t.CertType = common.GetCertType(t.CertFile)
	t.CertHash = crypt.FNV1a64(t.CertType, t.CertFile, t.KeyFile)
	t.Flow = new(Flow)
	s.JsonDb.Hosts.Store(t.Id, t)
	s.JsonDb.StoreHostToJsonFile()
	return nil
}

// GetHost 分页获取主机列表
//
// 参数:
//
//	start: 起始位置（分页）
//	length: 每页数量
//	id: 客户端ID过滤，0表示不限制
//	search: 搜索关键字（匹配ID、主机名、备注、客户端vkey）
//
// 返回:
//
//	[]*Host: 主机列表
//	int: 总数量
func (s *DbUtils) GetHost(start, length int, id int, search string) ([]*Host, int) {
	list := make([]*Host, 0)
	var cnt int
	originLength := length
	keys := GetMapKeys(&s.JsonDb.Hosts, false, "", "")
	for _, key := range keys {
		if value, ok := s.JsonDb.Hosts.Load(key); ok {
			v := value.(*Host)
			if search != "" && !(v.Id == common.GetIntNoErrByStr(search) || common.ContainsFold(v.Host, search) || common.ContainsFold(v.Remark, search) || common.ContainsFold(v.Client.VerifyKey, search)) {
				continue
			}
			if id == 0 || v.Client.Id == id {
				cnt++
				if start--; start < 0 {
					if originLength == 0 {
						list = append(list, v)
					} else if length--; length >= 0 {
						list = append(list, v)
					}
				}
			}
		}
	}
	return list, cnt
}

// DelClient 删除指定ID的客户端
// 停止速率限制器，移除vkey索引
//
// 参数:
//
//	id: 客户端ID
//
// 返回:
//
//	error: 错误信息
func (s *DbUtils) DelClient(id int) error {
	if v, ok := s.JsonDb.Clients.Load(id); ok {
		c := v.(*Client)
		Blake2bVkeyIndex.Remove(crypt.Blake2b(c.VerifyKey))
		if c.Rate != nil {
			c.Rate.Stop()
		}
	}
	s.JsonDb.Clients.Delete(id)
	s.JsonDb.StoreClientsToJsonFile()
	return nil
}

// NewClient 创建新客户端
// 验证vkey和用户名唯一性，初始化速率限制器
//
// 参数:
//
//	c: 客户端配置
//
// 返回:
//
//	error: 错误信息
func (s *DbUtils) NewClient(c *Client) error {
	var isNotSet bool
	if c.WebUserName != "" && !s.VerifyUserName(c.WebUserName, c.Id) {
		return errors.New("web login username duplicate, please reset")
	}
	c.EnsureWebPassword()
reset:
	if c.VerifyKey == "" || isNotSet {
		isNotSet = true
		c.VerifyKey = crypt.GetRandomString(16, c.Id)
	}
	if !s.VerifyVkey(c.VerifyKey, c.Id) {
		if isNotSet {
			goto reset
		}
		return errors.New("vkey duplicate, please reset")
	}
	if c.RateLimit == 0 {
		c.Rate = rate.NewRate(int64(2 << 23))
	} else if c.Rate == nil {
		c.Rate = rate.NewRate(int64(c.RateLimit * 1024))
	}
	c.Rate.Start()
	if c.Id == 0 {
		c.Id = int(s.JsonDb.GetClientId())
	}
	if c.Flow == nil {
		c.Flow = new(Flow)
	}
	s.JsonDb.Clients.Store(c.Id, c)
	Blake2bVkeyIndex.Add(crypt.Blake2b(c.VerifyKey), c.Id)
	s.JsonDb.StoreClientsToJsonFile()
	return nil
}

// VerifyVkey 验证vkey是否唯一（排除指定ID）
//
// 参数:
//
//	vkey: 待验证的vkey
//	id: 要排除的客户端ID
//
// 返回:
//
//	bool: true表示唯一，false表示重复
func (s *DbUtils) VerifyVkey(vkey string, id int) (res bool) {
	res = true
	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*Client)
		if v.VerifyKey == vkey && v.Id != id {
			res = false
			return false
		}
		return true
	})
	return res
}

// VerifyUserName 验证Web登录用户名是否唯一（排除指定ID）
//
// 参数:
//
//	username: 待验证的用户名
//	id: 要排除的客户端ID
//
// 返回:
//
//	bool: true表示唯一，false表示重复
func (s *DbUtils) VerifyUserName(username string, id int) (res bool) {
	res = true
	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*Client)
		if v.WebUserName == username && v.Id != id {
			res = false
			return false
		}
		return true
	})
	return res
}

// UpdateClient 更新客户端配置
// 更新索引和速率限制器
//
// 参数:
//
//	t: 客户端配置
//
// 返回:
//
//	error: 错误信息
func (s *DbUtils) UpdateClient(t *Client) error {
	if v, ok := s.JsonDb.Clients.Load(t.Id); ok {
		c := v.(*Client)
		Blake2bVkeyIndex.Remove(crypt.Blake2b(c.VerifyKey))
		if c.Rate != nil {
			c.Rate.Stop()
		}
	}

	s.JsonDb.Clients.Store(t.Id, t)
	Blake2bVkeyIndex.Add(crypt.Blake2b(t.VerifyKey), t.Id)
	if t.RateLimit > 0 {
		t.Rate = rate.NewRate(int64(t.RateLimit * 1024))
		t.Rate.Start()
	} else {
		t.Rate = rate.NewRate(int64(2 << 23))
		t.Rate.Start()
	}
	return nil
}

// IsPubClient 判断是否为公共客户端
// 公共客户端不显示在列表中（NoDisplay=true）
//
// 参数:
//
//	id: 客户端ID
//
// 返回:
//
//	bool: true表示是公共客户端
func (s *DbUtils) IsPubClient(id int) bool {
	client, err := s.GetClient(id)
	if err == nil {
		return client.NoDisplay
	}
	return false
}

// GetClient 根据ID获取客户端
//
// 参数:
//
//	id: 客户端ID
//
// 返回:
//
//	*Client: 客户端对象
//	error: 错误信息
func (s *DbUtils) GetClient(id int) (c *Client, err error) {
	if v, ok := s.JsonDb.Clients.Load(id); ok {
		c = v.(*Client)
		return
	}
	err = errors.New("can not find client")
	return
}

// GetGlobal 获取全局配置
//
// 返回:
//
//	*Glob: 全局配置对象
func (s *DbUtils) GetGlobal() (c *Glob) {
	return s.JsonDb.Global
}

// GetHostById 根据ID获取主机
//
// 参数:
//
//	id: 主机ID
//
// 返回:
//
//	*Host: 主机对象
//	error: 错误信息
func (s *DbUtils) GetHostById(id int) (h *Host, err error) {
	if v, ok := s.JsonDb.Hosts.Load(id); ok {
		h = v.(*Host)
		return
	}
	err = errors.New("the host could not be parsed")
	return
}

// GetInfoByHost 根据主机名和请求路径查找最佳匹配的主机配置
// 支持通配符匹配（*.example.com）和路径匹配
// 优先级：路径最长匹配 > 域名最长匹配 > 精确匹配
//
// 参数:
//
//	host: 主机名
//	r: HTTP请求对象
//
// 返回:
//
//	*Host: 最佳匹配的主机配置
//	error: 错误信息
func (s *DbUtils) GetInfoByHost(host string, r *http.Request) (h *Host, err error) {
	host = common.GetIpByAddr(host)
	hostLength := len(host)

	requestPath := r.RequestURI
	if requestPath == "" {
		requestPath = "/"
	}

	scheme := r.URL.Scheme

	ids := HostIndex.Lookup(host)
	if len(ids) == 0 {
		return nil, errors.New("the host could not be parsed")
	}

	var bestMatch *Host
	var bestDomainLength int
	var bestLocationLength int
	for _, id := range ids {
		value, ok := s.JsonDb.Hosts.Load(id)
		if !ok {
			continue
		}
		v := value.(*Host)

		if v.IsClose || (v.Scheme != "all" && v.Scheme != scheme) {
			continue
		}

		curDomainLength := len(strings.TrimPrefix(v.Host, "*"))
		if hostLength < curDomainLength {
			continue
		}

		equaled := v.Host == host
		matched := equaled || (strings.HasPrefix(v.Host, "*") && strings.HasSuffix(host, v.Host[1:]))
		if !matched {
			continue
		}

		location := v.Location
		if location == "" {
			location = "/"
		}

		if !strings.HasPrefix(requestPath, location) {
			continue
		}

		curLocationLength := len(location)
		if bestMatch == nil {
			bestMatch = v
			bestDomainLength = curDomainLength
			bestLocationLength = curLocationLength
			continue
		}
		if curLocationLength > bestLocationLength {
			bestMatch = v
			bestDomainLength = curDomainLength
			bestLocationLength = curLocationLength
			continue
		}
		if curLocationLength == bestLocationLength {
			if curDomainLength > bestDomainLength {
				bestMatch = v
				bestDomainLength = curDomainLength
				bestLocationLength = curLocationLength
				continue
			}
			if equaled {
				bestMatch = v
				bestDomainLength = curDomainLength
				bestLocationLength = curLocationLength
				continue
			}
		}
	}

	if bestMatch != nil {
		return bestMatch, nil
	}
	return nil, errors.New("the host could not be parsed")
}

// FindCertByHost 根据主机名查找证书配置
// 用于HTTPS连接的证书选择，优先匹配根路径
//
// 参数:
//
//	host: 主机名
//
// 返回:
//
//	*Host: 主机配置（包含证书信息）
//	error: 错误信息
func (s *DbUtils) FindCertByHost(host string) (*Host, error) {
	if host == "" {
		return nil, errors.New("invalid Host")
	}

	host = common.GetIpByAddr(host)
	hostLength := len(host)

	ids := HostIndex.Lookup(host)
	if len(ids) == 0 {
		return nil, errors.New("the host could not be parsed")
	}

	var bestMatch *Host
	var bestDomainLength int
	for _, id := range ids {
		value, ok := s.JsonDb.Hosts.Load(id)
		if !ok {
			continue
		}
		v := value.(*Host)

		if v.IsClose || (v.Scheme == "http") {
			continue
		}

		curDomainLength := len(strings.TrimPrefix(v.Host, "*"))
		if hostLength < curDomainLength {
			continue
		}

		equaled := v.Host == host
		matched := false
		location := v.Location == "/" || v.Location == ""
		if equaled {
			if location {
				bestMatch = v
				break
			}
			matched = true
		} else if strings.HasPrefix(v.Host, "*") && strings.HasSuffix(host, v.Host[1:]) {
			matched = true
		}
		if !matched {
			continue
		}

		if bestMatch == nil {
			bestMatch = v
			bestDomainLength = curDomainLength
			continue
		}
		if curDomainLength > bestDomainLength {
			bestMatch = v
			bestDomainLength = curDomainLength
			continue
		}
		if curDomainLength == bestDomainLength {
			if equaled && (len(v.Location) <= len(bestMatch.Location) || strings.HasPrefix(bestMatch.Host, "*")) {
				bestMatch = v
				bestDomainLength = curDomainLength
				continue
			}
			if (len(v.Location) <= len(bestMatch.Location)) && strings.HasPrefix(bestMatch.Host, "*") {
				bestMatch = v
				bestDomainLength = curDomainLength
				continue
			}
		}
	}
	if bestMatch != nil {
		return bestMatch, nil
	}
	return nil, errors.New("the host could not be parsed")
}
