// Package server 提供nps服务器的核心功能
// 包括服务器启动、任务管理、客户端管理、流量统计等核心业务逻辑
package server

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/beego/beego"
	"github.com/mycoool/nps/bridge"
	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/conn"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/index"
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/lib/rate"
	"github.com/mycoool/nps/lib/version"
	"github.com/mycoool/nps/server/connection"
	"github.com/mycoool/nps/server/proxy"
	"github.com/mycoool/nps/server/proxy/httpproxy"
	"github.com/mycoool/nps/server/tool"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

var (
	// Bridge 服务器桥接对象，负责与客户端的通信连接管理
	Bridge *bridge.Bridge
	// RunList 运行中的任务列表，key为任务ID，value为服务实例
	// 使用sync.Map保证并发安全
	RunList sync.Map //map[int]interface{}
	// once 用于确保某些初始化操作只执行一次
	once sync.Once
	// HttpProxyCache HTTP代理缓存，用于快速查找HTTP代理配置
	HttpProxyCache = index.NewAnyIntIndex()
)

// init 包初始化函数
// 初始化运行列表，并设置工具查找函数
func init() {
	// 初始化任务运行列表
	RunList = sync.Map{}
	// 设置任务查找回调函数，用于根据任务ID查找对应的拨号器
	tool.SetLookup(func(id int) (tool.Dialer, bool) {
		if v, ok := RunList.Load(id); ok {
			// 类型断言检查是否为隧道模式服务器
			if svr, ok := v.(*proxy.TunnelModeServer); ok {
				// 排除tunnel://类型的任务
				if !strings.Contains(svr.Task.Target.TargetStr, "tunnel://") {
					return svr, true
				}
			}
		}
		return nil, false
	})
}

// InitFromDb 从数据库初始化任务和客户端
// 该函数在服务器启动时调用，用于：
// 1. 创建本地代理客户端（如果启用）
// 2. 添加公共vkey客户端（如果配置了）
// 3. 加载所有状态为true的任务并启动
func InitFromDb() {
	if allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy"); allowLocalProxy {
		db := file.GetDb()
		if _, err := db.GetClient(-1); err != nil {
			local := new(file.Client)
			local.Id = -1
			local.Remark = "Local Proxy"
			local.Addr = "127.0.0.1"
			local.Cnf = new(file.Config)
			local.Flow = new(file.Flow)
			local.Rate = rate.NewRate(int64(2 << 23))
			local.Rate.Start()
			local.NowConn = 0
			local.Status = true
			local.ConfigConnAllow = true
			local.Version = version.VERSION
			local.VerifyKey = "localproxy"
			db.JsonDb.Clients.Store(local.Id, local)
			logs.Info("Auto create local proxy client.")
		}
	}

	//Add a public password
	if vkey := beego.AppConfig.String("public_vkey"); vkey != "" {
		c := file.NewClient(vkey, true, true)
		_ = file.GetDb().NewClient(c)
		RunList.Store(c.Id, nil)
		//RunList[c.Id] = nil
	}
	//Initialize services in server-side files
	file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		if value.(*file.Tunnel).Status {
			_ = AddTask(value.(*file.Tunnel))
		}
		return true
	})
}

// DealBridgeTask 处理桥接器发送的各种任务命令
// 这是一个核心的协程函数，通过channel监听并处理以下任务：
// 1. OpenHost: 打开/修改主机配置，清除HTTP代理缓存
// 2. OpenTask: 打开/重启任务，停止旧任务后启动新任务
// 3. CloseTask: 关闭任务
// 4. CloseClient: 关闭客户端，删除该客户端的所有任务和主机
// 5. SecretChan: 处理秘密链接连接
// 该函数会无限循环，持续处理来自bridge的命令
func DealBridgeTask() {
	for {
		select {
		case h := <-Bridge.OpenHost:
			if h != nil {
				HttpProxyCache.Remove(h.Id)
			}
		case t := <-Bridge.OpenTask:
			if t != nil {
				//_ = AddTask(t)
				_ = StopServer(t.Id)
				if err := StartTask(t.Id); err != nil {
					logs.Error("StartTask(%d) error: %v", t.Id, err)
				}
			}
		case t := <-Bridge.CloseTask:
			if t != nil {
				_ = StopServer(t.Id)
			}
		case id := <-Bridge.CloseClient:
			DelTunnelAndHostByClientId(id, true)
			if v, ok := file.GetDb().JsonDb.Clients.Load(id); ok {
				if v.(*file.Client).NoStore {
					_ = file.GetDb().DelClient(id)
				}
			}
		//case tunnel := <-Bridge.OpenTask:
		//	_ = StartTask(tunnel.Id)
		case s := <-Bridge.SecretChan:
			if s != nil {
				logs.Trace("New secret connection, addr %v", s.Conn.Conn.RemoteAddr())
				if t := file.GetDb().GetTaskByMd5Password(s.Password); t != nil {
					if t.Status {
						allowLocalProxy := beego.AppConfig.DefaultBool("allow_local_proxy", false)
						allowSecretLink := beego.AppConfig.DefaultBool("allow_secret_link", false)
						allowSecretLocal := beego.AppConfig.DefaultBool("allow_secret_local", false)
						go func() {
							if err := proxy.NewSecretServer(Bridge, t, allowLocalProxy, allowSecretLink, allowSecretLocal).HandleSecret(s.Conn); err != nil {
								logs.Error("HandleSecret error: %v", err)
							}
						}()
					} else {
						_ = s.Conn.Close()
						logs.Trace("This key %s cannot be processed,status is close", s.Password)
					}
				} else {
					logs.Trace("This key %s cannot be processed", s.Password)
					_ = s.Conn.Close()
				}
			}
		}
	}
}

// StartNewServer 启动一个新的服务器实例
// 该函数是nps服务器的核心启动函数，负责：
// 1. 创建并启动桥接器（Bridge），监听客户端连接
// 2. 启动P2P服务器（如果配置了p2p_port）
// 3. 启动桥接任务处理协程（DealBridgeTask）
// 4. 启动客户端流量统计协程（dealClientFlow）
// 5. 初始化仪表板数据
// 6. 根据配置创建并启动对应模式的服务（TCP/UDP/HTTP代理等）
//
// 参数:
//
//	bridgePort: 桥接器监听端口
//	cnf: 隧道配置
//	bridgeType: 桥接类型（tcp/kcp等）
//	bridgeDisconnect: 断开连接的超时时间
func StartNewServer(bridgePort int, cnf *file.Tunnel, bridgeType string, bridgeDisconnect int) {
	Bridge = bridge.NewTunnel(bridgePort, bridgeType, common.GetBoolByStr(beego.AppConfig.String("ip_limit")), &RunList, bridgeDisconnect)
	go func() {
		if err := Bridge.StartTunnel(); err != nil {
			logs.Error("start server bridge error %v", err)
			os.Exit(0)
		}
	}()
	if p, err := beego.AppConfig.Int("p2p_port"); err == nil {
		for i := 0; i < 3; i++ {
			port := p + i
			if common.TestUdpPort(port) {
				go func(p2pPort int) {
					if err := proxy.NewP2PServer(p2pPort).Start(); err != nil {
						logs.Error("P2P server start error: %v", err)
					}
				}(port)
				logs.Info("Started P2P Server on port %d", port)
			} else {
				logs.Error("Port %d is unavailable.", port)
			}
		}
	}
	go DealBridgeTask()
	go dealClientFlow()
	InitDashboardData()
	if svr := NewMode(Bridge, cnf); svr != nil {
		if err := svr.Start(); err != nil {
			logs.Error("%v", err)
		}
		RunList.Store(cnf.Id, svr)
		//RunList[cnf.Id] = svr
	} else {
		logs.Error("Incorrect startup mode %s", cnf.Mode)
	}
}

// dealClientFlow 客户端流量统计协程
// 每分钟触发一次，调用dealClientData()处理客户端数据更新
func dealClientFlow() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		dealClientData()
	}
}

// PingClient 向客户端发送ping请求，测量往返时间（RTT）
// 通过向指定客户端发送ping连接请求，计算并返回往返延迟时间（毫秒）
//
// 参数:
//
//	id: 客户端ID
//	addr: 客户端地址
//
// 返回:
//
//	int: 往返时间（毫秒），失败返回-1，无效ID返回0
func PingClient(id int, addr string) int {
	if id <= 0 {
		return 0
	}
	// 创建ping类型的连接
	link := conn.NewLink("ping", "", false, false, addr, false)
	link.Option.NeedAck = true
	start := time.Now()
	// 通过bridge向客户端发送连接信息
	target, err := Bridge.SendLinkInfo(id, link, nil)
	if err != nil {
		logs.Warn("get connection from client Id %d error %v", id, err)
		return -1
	}
	// 计算往返时间
	rtt := int(time.Since(start).Milliseconds())
	_ = target.Close()
	return rtt
}

// NewMode 根据模式名称创建对应的服务器实例
// nps支持多种隧道和代理模式，该函数根据配置的模式创建相应的服务对象
//
// 支持的模式:
//   - tcp: TCP隧道模式
//   - file: 文件服务模式
//   - mixProxy: 混合代理模式（HTTP+SOCKS5）
//   - socks5: SOCKS5代理模式
//   - httpProxy: HTTP代理模式
//   - tcpTrans: TCP透传模式
//   - udp: UDP隧道模式
//   - webServer: Web服务器模式（管理界面）
//   - httpHostServer: HTTP虚拟主机模式
//
// 参数:
//
//	Bridge: 桥接器对象
//	c: 隧道配置
//
// 返回:
//
//	proxy.Service: 代理服务实例
func NewMode(Bridge *bridge.Bridge, c *file.Tunnel) proxy.Service {
	var service proxy.Service
	allowLocalProxy := beego.AppConfig.DefaultBool("allow_local_proxy", false)
	switch c.Mode {
	case "tcp", "file":
		service = proxy.NewTunnelModeServer(proxy.ProcessTunnel, Bridge, c, allowLocalProxy)
	case "mixProxy", "socks5", "httpProxy":
		service = proxy.NewTunnelModeServer(proxy.ProcessMix, Bridge, c, allowLocalProxy)
		//service = proxy.NewSock5ModeServer(Bridge, c)
		//service = proxy.NewTunnelModeServer(proxy.ProcessHttp, Bridge, c)
	case "tcpTrans":
		service = proxy.NewTunnelModeServer(proxy.HandleTrans, Bridge, c, allowLocalProxy)
	case "udp":
		service = proxy.NewUdpModeServer(Bridge, c, allowLocalProxy)
	case "webServer":
		InitFromDb()
		t := &file.Tunnel{
			Port:   0,
			Mode:   "httpHostServer",
			Status: true,
		}
		_ = AddTask(t)
		service = NewWebServer(Bridge)
	case "httpHostServer":
		httpPort := connection.HttpPort
		httpsPort := connection.HttpsPort
		http3Port := connection.Http3Port
		//useCache, _ := beego.AppConfig.Bool("http_cache")
		//cacheLen, _ := beego.AppConfig.Int("http_cache_length")
		addOrigin, _ := beego.AppConfig.Bool("http_add_origin_header")
		httpOnlyPass := beego.AppConfig.String("x_nps_http_only")
		service = httpproxy.NewHttpProxy(Bridge, c, httpPort, httpsPort, http3Port, httpOnlyPass, addOrigin, allowLocalProxy, HttpProxyCache)
	}
	return service
}

// StopServer 停止指定ID的服务器
// 该函数会：
// 1. 更新数据库中任务的状态为false
// 2. 调用服务实例的Close方法停止服务
// 3. 从运行列表中移除该任务
//
// 参数:
//
//	id: 任务ID
//
// 返回:
//
//	error: 错误信息，nil表示成功
func StopServer(id int) error {
	if t, err := file.GetDb().GetTask(id); err != nil {
		return err
	} else {
		t.Status = false
		logs.Info("close port %d,remark %s,client id %d,task id %d", t.Port, t.Remark, t.Client.Id, t.Id)
		_ = file.GetDb().UpdateTask(t)
	}
	//if v, ok := RunList[id]; ok {
	if v, ok := RunList.Load(id); ok {
		if svr, ok := v.(proxy.Service); ok {
			if err := svr.Close(); err != nil {
				return err
			}
			logs.Info("stop server id %d", id)
		} else {
			logs.Warn("stop server id %d error", id)
		}
		//delete(RunList, id)
		RunList.Delete(id)
		return nil
	}
	return errors.New("task is not running")
}

// AddTask 添加并启动一个新的任务
// 该函数负责：
// 1. 检查端口是否可用
// 2. 创建流量存储定时器（如果配置了）
// 3. 根据模式创建相应的服务实例
// 4. 启动服务并加入到运行列表
//
// 参数:
//
//	t: 隧道任务配置
//
// 返回:
//
//	error: 错误信息，nil表示成功
func AddTask(t *file.Tunnel) error {
	if t.Mode == "secret" || t.Mode == "p2p" {
		logs.Info("secret task %s start ", t.Remark)
		//RunList[t.Id] = nil
		RunList.Store(t.Id, nil)
		return nil
	}
	if b := tool.TestServerPort(t.Port, t.Mode); !b && t.Mode != "httpHostServer" {
		logs.Error("taskId %d start error port %d open failed", t.Id, t.Port)
		return errors.New("the port open error")
	}
	if minute, err := beego.AppConfig.Int("flow_store_interval"); err == nil && minute > 0 {
		go flowSession(time.Minute * time.Duration(minute))
	}
	if svr := NewMode(Bridge, t); svr != nil {
		logs.Info("tunnel task %s start mode：%s port %d", t.Remark, t.Mode, t.Port)
		//RunList[t.Id] = svr
		RunList.Store(t.Id, svr)
		go func() {
			if err := svr.Start(); err != nil {
				logs.Error("clientId %d taskId %d start error %v", t.Client.Id, t.Id, err)
				//delete(RunList, t.Id)
				RunList.Delete(t.Id)
				return
			}
		}()
	} else {
		return errors.New("the mode is not correct")
	}
	return nil
}

// StartTask 启动指定ID的任务
// 从数据库获取任务配置，检查端口可用性后调用AddTask启动
//
// 参数:
//
//	id: 任务ID
//
// 返回:
//
//	error: 错误信息，nil表示成功
func StartTask(id int) error {
	if t, err := file.GetDb().GetTask(id); err != nil {
		return err
	} else {
		if !tool.TestServerPort(t.Port, t.Mode) {
			return errors.New("the port open error")
		}
		err = AddTask(t)
		if err != nil {
			return err
		}
		t.Status = true
		_ = file.GetDb().UpdateTask(t)
	}
	return nil
}

// DelTask 删除指定ID的任务
// 先停止任务运行，然后从数据库中删除
//
// 参数:
//
//	id: 任务ID
//
// 返回:
//
//	error: 错误信息，nil表示成功
func DelTask(id int) error {
	//if _, ok := RunList[id]; ok {
	if _, ok := RunList.Load(id); ok {
		if err := StopServer(id); err != nil {
			return err
		}
	}
	return file.GetDb().DelTask(id)
}

// GetTunnel 分页获取任务列表
// 支持按类型、客户端ID、关键字过滤，以及多字段排序
//
// 参数:
//
//	start: 起始位置（分页）
//	length: 每页数量，0表示全部
//	typeVal: 任务类型过滤（tcp、udp、socks5等）
//	clientId: 客户端ID过滤，0表示不限制
//	search: 搜索关键字（匹配ID、端口、密码、备注、目标地址）
//	sortField: 排序字段（Id、Port、Remark、Client.Id等）
//	order: 排序方式（asc升序、desc降序）
//
// 返回:
//
//	[]*file.Tunnel: 任务列表
//	int: 总数量
func GetTunnel(start, length int, typeVal string, clientId int, search string, sortField string, order string) ([]*file.Tunnel, int) {
	allList := make([]*file.Tunnel, 0) //store all Tunnel
	list := make([]*file.Tunnel, 0)
	originLength := length
	var cnt int
	keys := file.GetMapKeys(&file.GetDb().JsonDb.Tasks, false, "", "")

	//get all Tunnel and sort
	for _, key := range keys {
		if value, ok := file.GetDb().JsonDb.Tasks.Load(key); ok {
			v := value.(*file.Tunnel)
			if (typeVal != "" && v.Mode != typeVal || (clientId != 0 && v.Client.Id != clientId)) || (typeVal == "" && clientId != v.Client.Id) {
				continue
			}
			allList = append(allList, v)
		}
	}
	//sort by Id, Remark, TargetStr, Port, asc or desc
	switch sortField {
	case "Id":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Id < allList[j].Id })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Id > allList[j].Id })
		}
	case "Client.Id":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Client.Id < allList[j].Client.Id })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Client.Id > allList[j].Client.Id })
		}
	case "Remark":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Remark < allList[j].Remark })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Remark > allList[j].Remark })
		}
	case "Client.VerifyKey":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Client.VerifyKey < allList[j].Client.VerifyKey })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Client.VerifyKey > allList[j].Client.VerifyKey })
		}
	case "Target.TargetStr":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Target.TargetStr < allList[j].Target.TargetStr })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Target.TargetStr > allList[j].Target.TargetStr })
		}
	case "Port":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Port < allList[j].Port })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Port > allList[j].Port })
		}
	case "Mode":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Mode < allList[j].Mode })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Mode > allList[j].Mode })
		}
	case "TargetType":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].TargetType < allList[j].TargetType })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].TargetType > allList[j].TargetType })
		}
	case "Password":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Password < allList[j].Password })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Password > allList[j].Password })
		}
	case "HttpProxy":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].HttpProxy && !allList[j].HttpProxy })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return !allList[i].HttpProxy && allList[j].HttpProxy })
		}
	case "Socks5Proxy":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Socks5Proxy && !allList[j].Socks5Proxy })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return !allList[i].Socks5Proxy && allList[j].Socks5Proxy })
		}
	case "NowConn":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].NowConn < list[j].NowConn })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].NowConn > list[j].NowConn })
		}
	case "InletFlow":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.InletFlow < list[j].Flow.InletFlow })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.InletFlow > list[j].Flow.InletFlow })
		}
	case "ExportFlow":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.ExportFlow < list[j].Flow.ExportFlow })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.ExportFlow > list[j].Flow.ExportFlow })
		}
	case "TotalFlow":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool {
				return list[i].Flow.InletFlow+list[i].Flow.ExportFlow < list[j].Flow.InletFlow+list[j].Flow.ExportFlow
			})
		} else {
			sort.SliceStable(list, func(i, j int) bool {
				return list[i].Flow.InletFlow+list[i].Flow.ExportFlow > list[j].Flow.InletFlow+list[j].Flow.ExportFlow
			})
		}
	case "FlowRemain":
		asc := order == "asc"
		const mb = int64(1024 * 1024)
		rem := func(f *file.Flow) int64 {
			if f.FlowLimit == 0 {
				if asc {
					return math.MaxInt64
				}
				return math.MinInt64
			}
			return f.FlowLimit*mb - (f.InletFlow + f.ExportFlow)
		}
		sort.SliceStable(list, func(i, j int) bool {
			ri, rj := rem(list[i].Flow), rem(list[j].Flow)
			if asc {
				return ri < rj
			}
			return ri > rj
		})
	case "Flow.FlowLimit":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool {
				vi, vj := list[i].Flow.FlowLimit, list[j].Flow.FlowLimit
				return (vi != 0 && vj == 0) || (vi != 0 && vj != 0 && vi < vj)
			})
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.FlowLimit > list[j].Flow.FlowLimit })
		}
	case "Flow.TimeLimit", "TimeRemain":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool {
				ti, tj := list[i].Flow.TimeLimit, list[j].Flow.TimeLimit
				return (!ti.IsZero() && tj.IsZero()) || (!ti.IsZero() && !tj.IsZero() && ti.Before(tj))
			})
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.TimeLimit.After(list[j].Flow.TimeLimit) })
		}
	case "Status":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Status && !allList[j].Status })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return !allList[i].Status && allList[j].Status })
		}
	case "RunStatus":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].RunStatus && !allList[j].RunStatus })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return !allList[i].RunStatus && allList[j].RunStatus })
		}
	case "Client.IsConnect":
		if order == "asc" {
			sort.SliceStable(allList, func(i, j int) bool { return allList[i].Client.IsConnect && !allList[j].Client.IsConnect })
		} else {
			sort.SliceStable(allList, func(i, j int) bool { return !allList[i].Client.IsConnect && allList[j].Client.IsConnect })
		}
	}

	//search
	for _, key := range allList {
		if value, ok := file.GetDb().JsonDb.Tasks.Load(key.Id); ok {
			v := value.(*file.Tunnel)
			if (typeVal != "" && v.Mode != typeVal || (clientId != 0 && v.Client.Id != clientId)) || (typeVal == "" && clientId != v.Client.Id) {
				continue
			}
			if search != "" && !(v.Id == common.GetIntNoErrByStr(search) || v.Port == common.GetIntNoErrByStr(search) || common.ContainsFold(v.Password, search) || common.ContainsFold(v.Remark, search) || common.ContainsFold(v.Target.TargetStr, search)) {
				continue
			}
			cnt++
			if _, ok := Bridge.Client.Load(v.Client.Id); ok {
				v.Client.IsConnect = true
			} else {
				v.Client.IsConnect = false
			}
			if start--; start < 0 {
				if originLength == 0 {
					if _, ok := RunList.Load(v.Id); ok {
						v.RunStatus = true
					} else {
						v.RunStatus = false
					}
					list = append(list, v)
				} else if length--; length >= 0 {
					//if _, ok := RunList[v.Id]; ok {
					if _, ok := RunList.Load(v.Id); ok {
						v.RunStatus = true
					} else {
						v.RunStatus = false
					}
					list = append(list, v)
				}
			}
		}
	}
	return list, cnt
}

// GetHostList 分页获取主机列表
// 支持按客户端ID、关键字过滤，以及多字段排序
//
// 参数:
//
//	start: 起始位置（分页）
//	length: 每页数量
//	clientId: 客户端ID过滤，0表示不限制
//	search: 搜索关键字（匹配ID、主机名、备注、客户端vkey）
//	sortField: 排序字段（Id、Host、Remark、Scheme等）
//	order: 排序方式（asc升序、desc降序）
//
// 返回:
//
//	[]*file.Host: 主机列表
//	int: 总数量
func GetHostList(start, length, clientId int, search, sortField, order string) (list []*file.Host, cnt int) {
	list, cnt = file.GetDb().GetHost(start, length, clientId, search)
	//sort by Id, Remark..., asc or desc
	switch sortField {
	case "Id":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Id < list[j].Id })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Id > list[j].Id })
		}
	case "Client.Id":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Client.Id < list[j].Client.Id })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Client.Id > list[j].Client.Id })
		}
	case "Remark":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Remark < list[j].Remark })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Remark > list[j].Remark })
		}
	case "Client.VerifyKey":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Client.VerifyKey < list[j].Client.VerifyKey })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Client.VerifyKey > list[j].Client.VerifyKey })
		}
	case "Host":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Host < list[j].Host })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Host > list[j].Host })
		}
	case "Scheme":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Scheme < list[j].Scheme })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Scheme > list[j].Scheme })
		}
	case "TargetIsHttps":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].TargetIsHttps && !list[j].TargetIsHttps })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].TargetIsHttps && list[j].TargetIsHttps })
		}
	case "Target.TargetStr":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Target.TargetStr < list[j].Target.TargetStr })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Target.TargetStr > list[j].Target.TargetStr })
		}
	case "Location":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Location < list[j].Location })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Location > list[j].Location })
		}
	case "PathRewrite":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].PathRewrite < list[j].PathRewrite })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].PathRewrite > list[j].PathRewrite })
		}
	case "CertType":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].CertType < list[j].CertType })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].CertType > list[j].CertType })
		}
	case "AutoSSL":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].AutoSSL && !list[j].AutoSSL })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].AutoSSL && list[j].AutoSSL })
		}
	case "AutoHttps":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].AutoHttps && !list[j].AutoHttps })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].AutoHttps && list[j].AutoHttps })
		}
	case "AutoCORS":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].AutoCORS && !list[j].AutoCORS })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].AutoCORS && list[j].AutoCORS })
		}
	case "CompatMode":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].CompatMode && !list[j].CompatMode })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].CompatMode && list[j].CompatMode })
		}
	case "HttpsJustProxy":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].HttpsJustProxy && !list[j].HttpsJustProxy })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].HttpsJustProxy && list[j].HttpsJustProxy })
		}
	case "TlsOffload":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].TlsOffload && !list[j].TlsOffload })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].TlsOffload && list[j].TlsOffload })
		}
	case "NowConn":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].NowConn < list[j].NowConn })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].NowConn > list[j].NowConn })
		}
	case "InletFlow":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.InletFlow < list[j].Flow.InletFlow })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.InletFlow > list[j].Flow.InletFlow })
		}
	case "ExportFlow":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.ExportFlow < list[j].Flow.ExportFlow })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.ExportFlow > list[j].Flow.ExportFlow })
		}
	case "TotalFlow":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool {
				return list[i].Flow.InletFlow+list[i].Flow.ExportFlow < list[j].Flow.InletFlow+list[j].Flow.ExportFlow
			})
		} else {
			sort.SliceStable(list, func(i, j int) bool {
				return list[i].Flow.InletFlow+list[i].Flow.ExportFlow > list[j].Flow.InletFlow+list[j].Flow.ExportFlow
			})
		}
	case "FlowRemain":
		asc := order == "asc"
		const mb = int64(1024 * 1024)
		rem := func(f *file.Flow) int64 {
			if f.FlowLimit == 0 {
				if asc {
					return math.MaxInt64
				}
				return math.MinInt64
			}
			return f.FlowLimit*mb - (f.InletFlow + f.ExportFlow)
		}
		sort.SliceStable(list, func(i, j int) bool {
			ri, rj := rem(list[i].Flow), rem(list[j].Flow)
			if asc {
				return ri < rj
			}
			return ri > rj
		})
	case "Flow.FlowLimit":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool {
				vi, vj := list[i].Flow.FlowLimit, list[j].Flow.FlowLimit
				return (vi != 0 && vj == 0) || (vi != 0 && vj != 0 && vi < vj)
			})
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.FlowLimit > list[j].Flow.FlowLimit })
		}
	case "Flow.TimeLimit", "TimeRemain":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool {
				ti, tj := list[i].Flow.TimeLimit, list[j].Flow.TimeLimit
				return (!ti.IsZero() && tj.IsZero()) || (!ti.IsZero() && !tj.IsZero() && ti.Before(tj))
			})
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.TimeLimit.After(list[j].Flow.TimeLimit) })
		}
	case "IsClose":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].IsClose && !list[j].IsClose })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].IsClose && list[j].IsClose })
		}
	case "Client.IsConnect":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Client.IsConnect && !list[j].Client.IsConnect })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].Client.IsConnect && list[j].Client.IsConnect })
		}
	}
	return
}

// GetClientList 分页获取客户端列表
// 支持按关键字、客户端ID过滤，以及多字段排序
//
// 参数:
//
//	start: 起始位置（分页）
//	length: 每页数量
//	search: 搜索关键字（匹配ID、vkey、备注）
//	sortField: 排序字段（Id、Addr、Remark、VerifyKey、Version、NowConn等）
//	order: 排序方式（asc升序、desc降序）
//	clientId: 客户端ID过滤，0表示不限制
//
// 返回:
//
//	[]*file.Client: 客户端列表
//	int: 总数量
func GetClientList(start, length int, search, sortField, order string, clientId int) (list []*file.Client, cnt int) {
	list, cnt = file.GetDb().GetClientList(start, length, search, sortField, order, clientId)
	//sort by Id, Remark, Port..., asc or desc
	switch sortField {
	case "Id":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Id < list[j].Id })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Id > list[j].Id })
		}
	case "Addr":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Addr < list[j].Addr })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Addr > list[j].Addr })
		}
	case "LocalAddr":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].LocalAddr < list[j].LocalAddr })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].LocalAddr > list[j].LocalAddr })
		}
	case "Remark":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Remark < list[j].Remark })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Remark > list[j].Remark })
		}
	case "VerifyKey":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].VerifyKey < list[j].VerifyKey })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].VerifyKey > list[j].VerifyKey })
		}
	case "TotalFlow":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool {
				return list[i].Flow.InletFlow+list[i].Flow.ExportFlow < list[j].Flow.InletFlow+list[j].Flow.ExportFlow
			})
		} else {
			sort.SliceStable(list, func(i, j int) bool {
				return list[i].Flow.InletFlow+list[i].Flow.ExportFlow > list[j].Flow.InletFlow+list[j].Flow.ExportFlow
			})
		}
	case "FlowRemain":
		asc := order == "asc"
		const mb = int64(1024 * 1024)
		rem := func(f *file.Flow) int64 {
			if f.FlowLimit == 0 {
				if asc {
					return math.MaxInt64
				}
				return math.MinInt64
			}
			return f.FlowLimit*mb - (f.InletFlow + f.ExportFlow)
		}
		sort.SliceStable(list, func(i, j int) bool {
			ri, rj := rem(list[i].Flow), rem(list[j].Flow)
			if asc {
				return ri < rj
			}
			return ri > rj
		})
	case "NowConn":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].NowConn < list[j].NowConn })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].NowConn > list[j].NowConn })
		}
	case "Version":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Version < list[j].Version })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Version > list[j].Version })
		}
	case "Mode":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Mode < list[j].Mode })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Mode > list[j].Mode })
		}
	case "Rate.NowRate":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Rate.NowRate < list[j].Rate.NowRate })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Rate.NowRate > list[j].Rate.NowRate })
		}
	case "Flow.FlowLimit":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool {
				vi, vj := list[i].Flow.FlowLimit, list[j].Flow.FlowLimit
				return (vi != 0 && vj == 0) || (vi != 0 && vj != 0 && vi < vj)
			})
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.FlowLimit > list[j].Flow.FlowLimit })
		}
	case "Flow.TimeLimit", "TimeRemain":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool {
				ti, tj := list[i].Flow.TimeLimit, list[j].Flow.TimeLimit
				return (!ti.IsZero() && tj.IsZero()) || (!ti.IsZero() && !tj.IsZero() && ti.Before(tj))
			})
		} else {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Flow.TimeLimit.After(list[j].Flow.TimeLimit) })
		}
	case "Status":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].Status && !list[j].Status })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].Status && list[j].Status })
		}
	case "IsConnect":
		if order == "asc" {
			sort.SliceStable(list, func(i, j int) bool { return list[i].IsConnect && !list[j].IsConnect })
		} else {
			sort.SliceStable(list, func(i, j int) bool { return !list[i].IsConnect && list[j].IsConnect })
		}
	}
	dealClientData()
	return
}

// dealClientData 处理和更新客户端数据
// 该函数负责：
// 1. 更新客户端的连接状态（IsConnect）
// 2. 更新客户端的最后在线时间
// 3. 获取并更新客户端版本信息
// 4. 统计每个客户端的流量（InletFlow和ExportFlow）
// 注意：该函数会先清空所有客户端的InletFlow和ExportFlow，然后从Hosts和Tasks中重新统计
func dealClientData() {
	//logs.Info("dealClientData.........")
	file.GetDb().JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*file.Client)
		if vv, ok := Bridge.Client.Load(v.Id); ok {
			v.IsConnect = true
			v.LastOnlineTime = time.Now().Format("2006-01-02 15:04:05")
			cli := vv.(*bridge.Client)
			node, ok := cli.GetNodeByUUID(cli.LastUUID)
			var ver string
			if ok {
				ver = node.Version
			}
			count := cli.NodeCount()
			if count > 1 {
				ver = fmt.Sprintf("%s(%d)", ver, cli.NodeCount())
			}
			v.Version = ver
		} else if v.Id <= 0 {
			if allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy"); allowLocalProxy {
				v.IsConnect = v.Status
				v.Version = version.VERSION
				v.Mode = "local"
				v.LocalAddr = common.GetOutboundIP().String()
				// Add Local Client
				if _, exists := Bridge.Client.Load(v.Id); !exists && v.Status {
					Bridge.Client.Store(v.Id, bridge.NewClient(v.Id, bridge.NewNode("127.0.0.1", version.VERSION, version.GetLatestIndex())))
					logs.Debug("Inserted virtual client for ID %d", v.Id)
				}
			} else {
				v.IsConnect = false
			}
		} else {
			v.IsConnect = false
		}
		v.InletFlow = 0
		v.ExportFlow = 0
		return true
	})
	file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
		h := value.(*file.Host)
		c, err := file.GetDb().GetClient(h.Client.Id)
		if err != nil {
			return true
		}
		c.InletFlow += h.Flow.InletFlow
		c.ExportFlow += h.Flow.ExportFlow
		return true
	})
	file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		t := value.(*file.Tunnel)
		c, err := file.GetDb().GetClient(t.Client.Id)
		if err != nil {
			return true
		}
		c.InletFlow += t.Flow.InletFlow
		c.ExportFlow += t.Flow.ExportFlow
		return true
	})
}

// DelTunnelAndHostByClientId 根据客户端ID删除所有关联的任务和主机
//
// 参数:
//
//	clientId: 客户端ID
//	justDelNoStore: 是否仅删除NoStore为true的项
//	                 false: 删除该客户端的所有任务和主机
//	                 true: 仅删除不持久化的任务和主机
func DelTunnelAndHostByClientId(clientId int, justDelNoStore bool) {
	var ids []int
	file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		v := value.(*file.Tunnel)
		if justDelNoStore && !v.NoStore {
			return true
		}
		if v.Client.Id == clientId {
			ids = append(ids, v.Id)
		}
		return true
	})
	for _, id := range ids {
		_ = DelTask(id)
	}
	ids = ids[:0]
	file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
		v := value.(*file.Host)
		if justDelNoStore && !v.NoStore {
			return true
		}
		if v.Client.Id == clientId {
			ids = append(ids, v.Id)
		}
		return true
	})
	for _, id := range ids {
		HttpProxyCache.Remove(id)
		_ = file.GetDb().DelHost(id)
	}
}

// DelClientConnect 关闭指定客户端的连接
// 从bridge中移除客户端连接，断开该客户端与服务器的连接
//
// 参数:
//
//	clientId: 客户端ID
func DelClientConnect(clientId int) {
	Bridge.DelClient(clientId)
}

var (
	// Cache
	cacheMu         sync.RWMutex
	dashboardCache  map[string]interface{}
	lastRefresh     time.Time
	lastFullRefresh time.Time

	// Net IO
	samplerOnce    sync.Once
	lastBytesSent  uint64
	lastBytesRecv  uint64
	lastSampleTime time.Time
	ioSendRate     atomic.Value // float64
	ioRecvRate     atomic.Value // float64
)

// startSpeedSampler 启动网络IO速率采样器
// 通过定时采样网络IO计数器，计算发送和接收速率（字节/秒）
// 使用samplerOnce确保只启动一次采样协程
func startSpeedSampler() {
	samplerOnce.Do(func() {
		// 初始化初始值
		if io1, _ := net.IOCounters(false); len(io1) > 0 {
			lastBytesSent = io1[0].BytesSent
			lastBytesRecv = io1[0].BytesRecv
		}
		lastSampleTime = time.Now()

		// 启动采样协程
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for now := range ticker.C {
				if io2, _ := net.IOCounters(false); len(io2) > 0 {
					sent := io2[0].BytesSent
					recv := io2[0].BytesRecv
					elapsed := now.Sub(lastSampleTime).Seconds()

					// 计算速率（字节/秒）
					rateSent := float64(sent-lastBytesSent) / elapsed
					rateRecv := float64(recv-lastBytesRecv) / elapsed

					ioSendRate.Store(rateSent)
					ioRecvRate.Store(rateRecv)

					// 更新采样点
					lastBytesSent = sent
					lastBytesRecv = recv
					lastSampleTime = now
				}
			}
		}()
	})
}

// InitDashboardData 初始化仪表板数据
// 启动速率采样器并获取初始数据
func InitDashboardData() {
	startSpeedSampler()
	GetDashboardData(true)
}

// GetDashboardData 获取仪表板显示数据
// 包含服务器的各种统计信息：客户端数量、主机数量、流量统计、系统资源使用率等
//
// 参数:
//
//	force: 是否强制刷新完整数据
//
// 返回:
//
//	map[string]interface{}: 包含各种统计指标的map
func GetDashboardData(force bool) map[string]interface{} {
	cacheMu.RLock()
	cached := dashboardCache
	lastR := lastRefresh
	lastFR := lastFullRefresh
	cacheMu.RUnlock()

	if cached != nil && !force && time.Since(lastFR) < 5*time.Second {
		if time.Since(lastR) < 1*time.Second {
			return cached
		}

		tcpCount := 0
		file.GetDb().JsonDb.Clients.Range(func(key, value interface{}) bool {
			tcpCount += int(value.(*file.Client).NowConn)
			return true
		})

		var cpuVal interface{}
		if cpuPercent, err := cpu.Percent(0, true); err == nil {
			var sum float64
			for _, v := range cpuPercent {
				sum += v
			}
			if n := len(cpuPercent); n > 0 {
				cpuVal = math.Round(sum / float64(n))
			}
		}

		var loadVal interface{}
		if loads, err := load.Avg(); err == nil {
			loadVal = loads.String()
		}

		var swapVal interface{}
		if swap, err := mem.SwapMemory(); err == nil {
			swapVal = math.Round(swap.UsedPercent)
		}

		var virtVal interface{}
		if vir, err := mem.VirtualMemory(); err == nil {
			virtVal = math.Round(vir.UsedPercent)
		}

		protoVals := map[string]int64{}
		if pcounters, err := net.ProtoCounters(nil); err == nil {
			for _, v := range pcounters {
				if val, ok := v.Stats["CurrEstab"]; ok {
					protoVals[v.Protocol] = val
				}
			}
		}
		if _, ok := protoVals["tcp"]; !ok {
			if conns, err := net.Connections("tcp"); err == nil {
				protoVals["tcp"] = int64(len(conns))
			}
		}
		if _, ok := protoVals["udp"]; !ok {
			if conns, err := net.Connections("udp"); err == nil {
				protoVals["udp"] = int64(len(conns))
			}
		}

		var ioSend, ioRecv interface{}
		if v, ok := ioSendRate.Load().(float64); ok {
			ioSend = v
		}
		if v, ok := ioRecvRate.Load().(float64); ok {
			ioRecv = v
		}

		upTime := common.GetRunTime()

		now := time.Now()

		cacheMu.Lock()
		dst := dashboardCache
		if dst == nil {
			dst = cached
		}
		dst["upTime"] = upTime
		dst["tcpCount"] = tcpCount
		if cpuVal != nil {
			dst["cpu"] = cpuVal
		}
		if loadVal != nil {
			dst["load"] = loadVal
		}
		if swapVal != nil {
			dst["swap_mem"] = swapVal
		}
		if virtVal != nil {
			dst["virtual_mem"] = virtVal
		}
		for k, v := range protoVals {
			dst[k] = v
		}
		if ioSend != nil {
			dst["io_send"] = ioSend
		}
		if ioRecv != nil {
			dst["io_recv"] = ioRecv
		}
		lastRefresh = now
		cacheMu.Unlock()

		return dst
	}

	data := make(map[string]interface{})
	data["version"] = version.VERSION
	data["minVersion"] = GetMinVersion()
	data["hostCount"] = common.GetSyncMapLen(&file.GetDb().JsonDb.Hosts)
	data["clientCount"] = common.GetSyncMapLen(&file.GetDb().JsonDb.Clients)
	if beego.AppConfig.String("public_vkey") != "" { // remove public vkey
		data["clientCount"] = data["clientCount"].(int) - 1
	}

	dealClientData()

	c := 0
	var in, out int64
	file.GetDb().JsonDb.Clients.Range(func(key, value interface{}) bool {
		v := value.(*file.Client)
		if v.IsConnect {
			c++
		}
		clientIn := v.Flow.InletFlow - (v.InletFlow + v.ExportFlow)
		if clientIn < 0 {
			clientIn = 0
		}
		clientOut := v.Flow.ExportFlow - (v.InletFlow + v.ExportFlow)
		if clientOut < 0 {
			clientOut = 0
		}
		in += v.InletFlow + clientIn/2
		out += v.ExportFlow + clientOut/2
		return true
	})
	data["clientOnlineCount"] = c
	data["inletFlowCount"] = int(in)
	data["exportFlowCount"] = int(out)

	var tcpN, udpN, secretN, socks5N, p2pN, httpN int
	file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		t := value.(*file.Tunnel)
		switch t.Mode {
		case "tcp":
			tcpN++
		case "socks5":
			socks5N++
		case "httpProxy":
			httpN++
		case "mixProxy":
			if t.HttpProxy {
				httpN++
			}
			if t.Socks5Proxy {
				socks5N++
			}
		case "udp":
			udpN++
		case "p2p":
			p2pN++
		case "secret":
			secretN++
		}
		return true
	})
	data["tcpC"] = tcpN
	data["udpCount"] = udpN
	data["socks5Count"] = socks5N
	data["httpProxyCount"] = httpN
	data["secretCount"] = secretN
	data["p2pCount"] = p2pN

	bridgeType := beego.AppConfig.String("bridge_type")
	if bridgeType == "both" {
		bridgeType = "tcp"
	}
	data["bridgeType"] = bridgeType
	data["httpProxyPort"] = beego.AppConfig.String("http_proxy_port")
	data["httpsProxyPort"] = beego.AppConfig.String("https_proxy_port")
	data["ipLimit"] = beego.AppConfig.String("ip_limit")
	data["flowStoreInterval"] = beego.AppConfig.String("flow_store_interval")
	data["serverIp"] = common.GetServerIp(connection.P2pIp)
	data["serverIpv4"] = common.GetOutboundIP().String()
	data["serverIpv6"] = common.GetOutboundIPv6().String()
	data["p2pIp"] = connection.P2pIp
	data["p2pPort"] = connection.P2pPort
	data["p2pAddr"] = common.JoinHostPort(common.GetServerIp(connection.P2pIp), strconv.Itoa(connection.P2pPort))
	data["logLevel"] = beego.AppConfig.String("log_level")
	data["upTime"] = common.GetRunTime()
	data["upSecs"] = common.GetRunSecs()
	data["startTime"] = common.GetStartTime()

	tcpCount := 0
	file.GetDb().JsonDb.Clients.Range(func(key, value interface{}) bool {
		tcpCount += int(value.(*file.Client).NowConn)
		return true
	})
	data["tcpCount"] = tcpCount

	if cpuPercent, err := cpu.Percent(0, true); err == nil {
		var cpuAll float64
		for _, v := range cpuPercent {
			cpuAll += v
		}
		if n := len(cpuPercent); n > 0 {
			data["cpu"] = math.Round(cpuAll / float64(n))
		}
	}
	if loads, err := load.Avg(); err == nil {
		data["load"] = loads.String()
	}
	if swap, err := mem.SwapMemory(); err == nil {
		data["swap_mem"] = math.Round(swap.UsedPercent)
	}
	if vir, err := mem.VirtualMemory(); err == nil {
		data["virtual_mem"] = math.Round(vir.UsedPercent)
	}
	if pcounters, err := net.ProtoCounters(nil); err == nil {
		for _, v := range pcounters {
			if val, ok := v.Stats["CurrEstab"]; ok {
				data[v.Protocol] = val
			}
		}
	}
	if _, ok := data["tcp"]; !ok {
		if conns, err := net.Connections("tcp"); err == nil {
			data["tcp"] = int64(len(conns))
		}
	}
	if _, ok := data["udp"]; !ok {
		if conns, err := net.Connections("udp"); err == nil {
			data["udp"] = int64(len(conns))
		}
	}

	if v, ok := ioSendRate.Load().(float64); ok {
		data["io_send"] = v
	}
	if v, ok := ioRecvRate.Load().(float64); ok {
		data["io_recv"] = v
	}

	// chart
	deciles := tool.ChartDeciles()
	for i, v := range deciles {
		data["sys"+strconv.Itoa(i+1)] = v
	}

	now := time.Now()
	cacheMu.Lock()
	dashboardCache = data
	lastRefresh = now
	lastFullRefresh = now
	cacheMu.Unlock()

	return data
}

// GetVersion 获取当前服务器版本
func GetVersion() string {
	return version.VERSION
}

// GetMinVersion 获取支持的最低客户端版本
// 根据服务器安全模式确定最低兼容版本
func GetMinVersion() string {
	return version.GetMinVersion(bridge.ServerSecureMode)
}

// GetCurrentYear 获取当前年份
func GetCurrentYear() int {
	return time.Now().Year()
}

// flowSession 流量数据持久化定时器
// 将数据库中的Hosts、Tasks、Clients、Global数据定期保存到JSON文件
// 使用once确保定时器只启动一次
//
// 参数:
//
//	m: 定时间隔
func flowSession(m time.Duration) {
	// 立即保存一次
	file.GetDb().JsonDb.StoreHostToJsonFile()
	file.GetDb().JsonDb.StoreTasksToJsonFile()
	file.GetDb().JsonDb.StoreClientsToJsonFile()
	file.GetDb().JsonDb.StoreGlobalToJsonFile()
	// 启动定时保存协程
	once.Do(func() {
		go func() {
			ticker := time.NewTicker(m)
			defer ticker.Stop()
			for range ticker.C {
				file.GetDb().JsonDb.StoreHostToJsonFile()
				file.GetDb().JsonDb.StoreTasksToJsonFile()
				file.GetDb().JsonDb.StoreClientsToJsonFile()
				file.GetDb().JsonDb.StoreGlobalToJsonFile()
			}
		}()
	})
}
