# NPS 工作流程详解

## 目录
1. [项目概述](#项目概述)
2. [项目结构](#项目结构)
3. [核心组件](#核心组件)
4. [服务端工作流程](#服务端工作流程)
5. [客户端工作流程](#客户端工作流程)
6. [隧道建立与数据转发](#隧道建立与数据转发)
7. [支持的协议类型](#支持的协议类型)
8. [安全机制](#安全机制)
9. [完整流程图](#完整流程图)

---

## 项目概述

NPS (内网穿透服务) 是一款轻量高效的内网穿透代理服务器,采用客户端-服务端架构,允许将内网服务暴露到公网。

### 核心特性
- **多协议支持**: TCP、UDP、HTTP、HTTPS、SOCKS5 等多种协议转发
- **多连接方式**: TCP、TLS、KCP、QUIC、WebSocket、WebSocketSecure
- **Web管理界面**: 可视化管理客户端、隧道、流量监控
- **多路复用**: 在单个连接上传输多个数据流,提高效率
- **安全性**: 加密传输、流量限制、证书管理

---

## 项目结构

```
nps/
├── server/              # 服务端核心代码
│   ├── connection/     # 连接管理
│   ├── proxy/          # 各种协议代理实现
│   │   ├── tcp.go      # TCP隧道
│   │   ├── udp.go      # UDP隧道
│   │   ├── secret.go   # 秘密链接
│   │   ├── socks5.go   # SOCKS5代理
│   │   ├── p2p.go      # P2P直连
│   │   └── httpproxy/  # HTTP代理
│   ├── server.go       # 服务端主逻辑
│   ├── web.go          # Web管理界面
│   └── tool/           # 工具函数
│
├── client/              # 客户端核心代码
│   ├── client.go       # 客户端主逻辑
│   ├── control.go      # 连接控制与认证
│   ├── local.go        # 本地服务处理
│   ├── p2p.go          # P2P连接
│   ├── health.go       # 健康检查
│   └── file.go         # 文件服务器
│
├── bridge/             # 桥接器(服务端与客户端通信核心)
│   └── bridge.go       # 桥接器实现
│
├── lib/                # 公共库
│   ├── mux/           # 多路复用(Mux协议)
│   ├── conn/          # 连接封装
│   ├── crypt/         # 加密模块
│   ├── file/          # 数据库与配置管理
│   ├── common/        # 通用工具
│   └── logs/          # 日志模块
│
├── cmd/               # 命令行入口
│   ├── nps/           # 服务端入口
│   └── npc/           # 客户端入口
│
└── conf/              # 配置文件目录
```

---

## 核心组件

### 1. Bridge (桥接器)

**位置**: `bridge/bridge.go`

**职责**: 服务端与客户端之间的通信桥梁,管理所有客户端连接和任务分发

**核心字段**:
```go
type Bridge struct {
    TunnelPort         int           // 隧道端口
    Client             *sync.Map     // 客户端列表 (key: clientId)
    Register           *sync.Map     // IP注册表
    tunnelType         string        // 桥接类型 (tcp/kcp)
    VirtualTcpListener *conn.VirtualListener
    VirtualTlsListener *conn.VirtualListener
    VirtualWsListener  *conn.VirtualListener
    VirtualWssListener *conn.VirtualListener
    OpenHost           chan *file.Host    // 打开主机通道
    OpenTask           chan *file.Tunnel  // 打开任务通道
    CloseTask          chan *file.Tunnel  // 关闭任务通道
    CloseClient        chan int           // 关闭客户端通道
    SecretChan         chan *conn.Secret  // 秘密链接通道
}
```

**核心方法**:
- `StartTunnel()`: 启动隧道监听,支持多种协议
- `CliProcess()`: 处理客户端连接请求
- `SendLinkInfo()`: 发送链接信息到客户端

### 2. Mux (多路复用)

**位置**: `lib/mux/mux.go`, `lib/mux/tc.go`, `lib/mux/netpackager.go`

**职责**: 在单个物理连接上创建多个虚拟连接,提高资源利用率

**核心机制**:
```
单个物理连接 (TCP/TLS/QUIC)
    ├─ Mux连接1 (隧道数据)
    ├─ Mux连接2 (控制信号)
    ├─ Mux连接3 (心跳检测)
    └─ Mux连接N (其他数据)
```

**数据包格式**:
```
[Type(1字节)][Flag(1字节)][Length(2字节)][ID(2字节)][Content(Length字节)]
```

### 3. TRPClient (客户端核心)

**位置**: `client/client.go`

**职责**: 管理与服务器的连接、任务同步、数据转发

**核心字段**:
```go
type TRPClient struct {
    svrAddr        string        // 服务器地址
    bridgeConnType string        // 桥接连接类型 (tcp/tls/kcp/quic/ws/wss)
    vKey           string        // 客户端验证密钥
    tunnel         any           // Mux隧道连接
    signal         *conn.Conn    // 信号连接
    healthChecker  *HealthChecker
}
```

### 4. TunnelModeServer (隧道服务器)

**位置**: `server/proxy/tcp.go`

**职责**: 服务端监听指定端口,将连接转发到对应的客户端

**支持的隧道类型**:
- **TCP隧道**: 将TCP端口映射到内网服务
- **UDP隧道**: 将UDP端口映射到内网服务
- **HTTP代理**: HTTP正向代理
- **SOCKS5代理**: SOCKS5代理服务
- **主机转发**: 基于域名的HTTP/HTTPS转发

---

## 服务端工作流程

### 1. 服务端启动流程

```
启动nps服务
    ↓
读取配置文件 (nps.conf)
    ↓
初始化日志模块
    ↓
初始化数据库 (JSON文件或SQLite)
    ↓
创建Bridge桥接器
    ↓
启动多种协议监听器
    ├─ TCP监听器 (默认8024端口)
    ├─ TLS监听器
    ├─ KCP监听器
    ├─ QUIC监听器
    ├─ WebSocket监听器
    └─ WebSocketSecure监听器
    ↓
从数据库加载任务和客户端
    ├─ 加载所有状态为true的任务
    └─ 为每个任务启动对应的监听服务
    ↓
启动Web管理界面 (默认8080端口)
    ↓
启动心跳检测协程 (ping客户端)
    ↓
进入主循环,处理任务和客户端管理
```

**代码位置**: `server/server.go::InitFromDb()`, `bridge/bridge.go::StartTunnel()`

### 2. 服务端监听客户端连接

服务端通过Bridge监听多种协议端口:

```go
// TCP监听
conn.Accept(tcpListener, func(c net.Conn) {
    s.CliProcess(conn.NewConn(c), common.CONN_TCP)
})

// TLS监听
conn.Accept(tlsListener, func(c net.Conn) {
    s.CliProcess(conn.NewConn(tls.Server(c, tlsConfig)), common.CONN_TLS)
})

// KCP/QUIC/WS/WSS 类似...
```

**代码位置**: `bridge/bridge.go:76-180`

### 3. 客户端认证流程

当客户端连接时,服务端执行以下认证:

```
客户端连接请求
    ↓
接收连接类型和版本
    ↓
生成并保存UUID (用于后续连接验证)
    ↓
等待认证信息
    ├─ 接收vKey (客户端验证密钥)
    └─ 接收时间戳和签名 (防重放攻击)
    ↓
验证签名和时间戳
    ↓
查找客户端信息
    ↓
验证客户端状态 (是否启用、是否过期)
    ↓
创建Mux连接 (多路复用)
    ↓
发送任务配置到客户端
    ↓
客户端连接建立成功
```

**关键代码**:
```go
// 接收客户端类型
strType, err := c.ReadStr(2)
if strType == common.CONN_VERIFY {
    // 接收vKey
    vKey, err := c.ReadStr(32)
    // 验证客户端
    if client := checkClient(vKey); client != nil {
        // 创建Mux
        m := mux.NewMux(c.Conn, true)
        // 保存连接
        client.Conn = m
        client.Status = true
    }
}
```

**代码位置**: `bridge/bridge.go::CliProcess()`

### 4. 任务管理流程

服务端通过channel异步管理任务:

```go
// 服务端主循环
func DealBridgeTask() {
    for {
        select {
        case h := <-Bridge.OpenHost:
            // 打开主机配置 (HTTP域名转发)
            HttpProxyCache.Remove(h.Id)
            // 启动HTTP代理服务
            startHttpProxy(h)

        case t := <-Bridge.OpenTask:
            // 打开/重启任务
            StopServer(t.Id)
            StartTask(t.Id)

        case t := <-Bridge.CloseTask:
            // 关闭任务
            StopServer(t.Id)

        case id := <-Bridge.CloseClient:
            // 关闭客户端及其所有任务
            DelTunnelAndHostByClientId(id, true)
        }
    }
}
```

**代码位置**: `server/server.go:111-160`

---

## 客户端工作流程

### 1. 客户端启动流程

```
启动npc客户端
    ↓
读取配置文件
    ├─ 服务器地址
    ├─ vKey (验证密钥)
    ├─ 连接类型 (tcp/tls/kcp/quic/ws/wss)
    └─ 其他参数
    ↓
创建TRPClient实例
    ↓
启动连接协程
    ↓
循环尝试连接服务器
```

**代码位置**: `client/client.go::Start()`

### 2. 连接服务器流程

```
连接服务器
    ↓
建立基础连接 (TCP/TLS/KCP/QUIC/WS/WSS)
    ↓
发送连接类型和版本
    ↓
接收UUID
    ↓
发送认证信息
    ├─ vKey
    ├─ 时间戳
    └─ 签名
    ↓
等待认证结果
    ↓
认证成功
    ↓
创建Mux连接
    ↓
发送WORK_MAIN信号
    ↓
连接建立完成
```

**关键代码**:
```go
func (s *TRPClient) Start(ctx context.Context) {
    for {
        // 建立连接
        c, uuid, err := NewConn(s.bridgeConnType, s.vKey, s.svrAddr, s.proxyUrl)
        if err != nil {
            logs.Error("连接失败,5秒后重试: %v", err)
            time.Sleep(5 * time.Second)
            continue
        }
        s.uuid = uuid

        // 发送WORK_MAIN信号
        err = SendType(c, common.WORK_MAIN, s.uuid)
        if err != nil {
            logs.Error("发送信号失败: %v", err)
            continue
        }

        // 创建Mux连接
        s.tunnel = mux.NewMux(c.Conn, false)

        // 保存信号连接
        s.signal = c

        // 启动连接通道
        s.newChan()

        logs.Info("成功连接到服务器 %s", s.svrAddr)

        // 保持连接,监听服务器命令
        s.handleServerCommand()
    }
}
```

**代码位置**: `client/client.go:58-120`

### 3. 任务同步流程

```
客户端连接成功
    ↓
服务器发送任务配置
    ├─ TCP隧道配置
    ├─ UDP隧道配置
    ├─ HTTP代理配置
    ├─ SOCKS5配置
    ├─ 域名转发配置
    └─ 其他配置
    ↓
客户端解析配置
    ↓
根据配置类型启动对应服务
    ├─ TCP: 监听本地端口,转发到隧道
    ├─ UDP: 监听本地UDP端口
    ├─ HTTP: 启动HTTP代理服务
    └─ 域名转发: 本地反向代理
    ↓
任务启动完成
```

**代码位置**: `client/local.go::handleTask()`

### 4. 心跳保持

```
客户端连接建立
    ↓
启动心跳定时器 (每10秒)
    ↓
发送心跳包到服务器
    ↓
等待服务器响应
    ↓
响应超时判断
    ├─ 超时: 断开连接,重新连接
    └─ 正常: 继续保持
```

**代码位置**: `client/client.go:200-230`

---

## 隧道建立与数据转发

### 1. TCP隧道建立流程

```
外部用户访问服务端监听端口 (例如: 公网IP:8080)
    ↓
服务端TunnelModeServer接收连接
    ↓
验证客户端状态
    ├─ 流量限制检查
    ├─ 连接数限制检查
    └─ 时间限制检查
    ↓
创建Link对象 (封装连接信息)
    ↓
通过Bridge.SendLinkInfo()发送连接信息到客户端
    ↓
客户端接收连接请求
    ↓
客户端连接到本地目标服务 (例如: 127.0.0.1:80)
    ↓
建立双向数据转发
    ├─ 服务端 -> 客户端 -> 本地服务
    └─ 本地服务 -> 客户端 -> 服务端
    ↓
连接关闭,更新流量统计
```

**核心代码 (服务端)**:
```go
// server/proxy/tcp.go::process()
func (s *TunnelModeServer) process(c *conn.Conn, s2 *TunnelModeServer) error {
    // 获取客户端连接
    l := conn.NewLink(s.Task.Client.Id, c.Conn, s.Task)
    // 发送链接信息到客户端
    target, err := s2.Bridge.SendLinkInfo(s.Task.Client.Id, l, s.Task)
    if err != nil {
        return err
    }
    // 双向转发
    conn.CopyBuffer(c.Conn, target, l.Flow, s2, l.Conn, s2.Flow)
    return nil
}
```

**核心代码 (客户端)**:
```go
// client/local.go::handleTcp()
func handleTcp(link *conn.Link, task *file.Tunnel) {
    // 连接本地目标
    localConn, err := net.DialTimeout("tcp", task.Target.TargetStr, time.Second*5)
    if err != nil {
        link.Close()
        return
    }
    // 双向转发
    conn.CopyBuffer(link.Conn, localConn, link.Flow, nil, localConn, nil)
}
```

### 2. HTTP域名转发流程

```
外部用户访问: http://example.com/path
    ↓
DNS解析到服务端公网IP
    ↓
HTTP请求到达服务端
    ↓
服务端根据Host头匹配域名配置
    ↓
检查域名转发规则
    ├─ 是否启用
    ├─ 代理认证
    └─ IP白名单
    ↓
找到对应的客户端
    ↓
创建Link对象
    ↓
转发HTTP请求到客户端
    ↓
客户端接收请求
    ↓
客户端转发到本地服务 (保持原始Host头或修改)
    ↓
本地服务处理并返回响应
    ↓
响应路径逆向返回到用户
```

**代码位置**: `server/proxy/httpproxy/`, `client/local.go::handleHttp()`

### 3. UDP隧道流程

UDP采用连接跟踪机制:

```
服务端监听UDP端口
    ↓
接收UDP数据包
    ↓
检查会话表 (是否存在对应的会话)
    ├─ 存在: 转发到已有连接
    └─ 不存在: 创建新会话
    ↓
转发到客户端
    ↓
客户端转发到本地UDP服务
    ↓
响应数据包逆向返回
    ↓
会话超时清理
```

**代码位置**: `server/proxy/udp.go`, `client/local.go::handleUdp()`

### 4. P2P直连流程

```
客户端和服务端建立连接
    ↓
协商P2P参数
    ├─ 交换NAT类型
    ├─ 交换IP地址
    └─ 选择P2P协议 (QUIC/UDP)
    ↓
服务端尝试NAT打洞
    ↓
客户端同时发送探测包
    ↓
打洞成功,建立P2P连接
    ↓
数据直接在P2P连接上传输,不经过服务端
    ↓
P2P连接失败
    ↓
回退到服务端中继模式
```

**代码位置**: `server/proxy/p2p.go`, `client/p2p.go`

---

## 支持的协议类型

### 1. 连接协议 (客户端 -> 服务端)

| 协议 | 端口 | 特点 | 使用场景 |
|------|------|------|----------|
| TCP | 默认8024 | 稳定可靠 | 通用场景 |
| TLS | 自定义 | 加密传输 | 需要加密的场景 |
| KCP | 自定义 | 低延迟 | 对延迟敏感的应用 |
| QUIC | 自定义 | HTTP/3支持 | 现代Web应用 |
| WebSocket | 自定义 | 穿透防火墙 | 受限网络环境 |
| WebSocketSecure | 自定义 | WSS加密 | 受限且需要加密 |

### 2. 隧道类型 (服务端 -> 客户端)

| 类型 | 配置格式 | 用途 |
|------|---------|------|
| TCP | `tcp:端口` | TCP端口映射 |
| UDP | `udp:端口` | UDP端口映射 |
| HTTP代理 | `http:端口` | HTTP正向代理 |
| SOCKS5 | `socks5:端口` | SOCKS5代理 |
| 主机转发 | `host:域名:端口` | HTTP/HTTPS域名转发 |
| 混合代理 | `mix:端口` | HTTP+SOCKS5混合代理 |

---

## 安全机制

### 1. 认证机制

```
客户端连接
    ↓
提供vKey (验证密钥)
    ↓
生成签名 (使用时间戳 + vKey + 混淆)
    ↓
服务端验证
    ├─ vKey是否存在于数据库
    ├─ 签名是否正确
    └─ 时间戳是否在有效期内 (防重放攻击)
    ↓
认证通过
```

**关键代码**:
```go
// client/control.go::mkConn()
// 生成签名
timestamp := time.Now().Unix()
signature := crypt.Md5(timestampStr + vKey + pad)

// 服务端验证
bridge/bridge.go::verifyClient()
if time.Since(client.VerifyTime) > time.Minute*5 {
    return false // 时间戳过期
}
```

### 2. 加密传输

- **TLS连接**: 使用TLS加密所有通信
- **自定义加密**: 支持自定义加密算法
- **证书验证**: 可选的服务端/客户端双向证书验证

### 3. 流量和连接限制

```go
// 检查流量限制
if client.Flow.FlowLimit > 0 &&
    (client.Flow.ExportFlow + client.Flow.InletFlow) > client.Flow.FlowLimit*1024*1024 {
    return errors.New("流量超限")
}

// 检查时间限制
if !client.Flow.TimeLimit.IsZero() &&
    client.Flow.TimeLimit.Before(time.Now()) {
    return errors.New("服务已过期")
}

// 检查连接数限制
if client.NowConn >= client.GetConnNum() {
    return errors.New("连接数超限")
}
```

### 4. IP白名单

支持在隧道级别配置IP白名单,只允许特定IP访问。

---

## 完整流程图

### 整体架构图

```
┌─────────────┐                    ┌─────────────┐
│  外部用户    │                    │  内网服务    │
│              │                    │  (本地)     │
└──────┬──────┘                    └──────┬──────┘
       │                                 │
       │ 1. 访问公网IP:端口               │
       ↓                                 │
┌─────────────────────────────────────┐ │
│         NPS 服务端                   │ │
│  ┌─────────────────────────────┐    │ │
│  │   TunnelModeServer          │◄───┘
│  │   (监听公网端口)            │
│  └──────────┬──────────────────┘
│             │
│             │ 2. SendLinkInfo
│             ↓
│  ┌─────────────────────────────┐
│  │      Bridge (桥接器)         │
│  │  管理所有客户端连接和任务      │
│  └──────────┬──────────────────┘
│             │
├─────────────┼──────────────────────┐
│             │                      │
│             │ Mux连接               │
│             │ (多路复用)            │
│             │                      │
├─────────────┼──────────────────────┤
│             │                      │
│             ↓                      │
│  ┌─────────────────────────────┐  │
│  │       NPS 客户端             │  │
│  │  ┌──────────────────────┐   │  │
│  │  │   TRPClient          │   │  │
│  │  │   管理服务器连接      │   │  │
│  │  └──────────┬───────────┘   │  │
│  │             │ 3. 转发到本地    │  │
│  │             ↓                 │  │
│  │  ┌──────────────────────┐   │  │
│  │  │   Local Server       │   │  │
│  │  │   (监听本地端口)     │   │  │
│  │  └──────────┬───────────┘   │  │
│  └─────────────┼────────────────┘  │
│                │ 4. 访问内网服务    │
│                ↓                    │
│         ┌─────────────┐             │
│         │  内网服务    │             │
│         │  127.0.0.1  │             │
│         │  :80/22等   │             │
│         └─────────────┘             │
│                                      │
└──────────────────────────────────────┘
```

### 数据流转时序图

```
外部用户      服务端         Bridge        客户端        内网服务
   │             │              │             │             │
   │  1. 连接     │              │             │             │
   ├────────────>│              │             │             │
   │             │  2. SendLinkInfo           │             │
   │             ├────────────>│             │             │
   │             │              │  3. 转发请求  │             │
   │             │              ├────────────>│             │
   │             │              │             │  4. 连接    │
   │             │              │             ├───────────>│
   │             │              │             │  5. 响应    │
   │             │              │             │<───────────┤
   │             │              │  6. 返回数据 │             │
   │             │              │<────────────┤             │
   │  7. 响应     │              │             │             │
   │<────────────┤              │             │             │
   │             │              │             │             │
```

---

## 总结

NPS的工作流程可以概括为:

1. **服务端启动**: 初始化配置、数据库、Bridge,监听多种协议端口
2. **客户端连接**: 通过多种协议连接服务端,进行认证,建立Mux连接
3. **任务同步**: 服务端将隧道配置发送到客户端,客户端启动本地服务
4. **请求转发**: 外部请求 -> 服务端监听端口 -> Mux隧道 -> 客户端 -> 内网服务
5. **双向数据**: 数据在公网和内网之间双向流动,支持多种协议

**核心技术**:
- **多路复用(Mux)**: 在单个连接上传输多个数据流,提高效率
- **多协议支持**: 灵活适应不同网络环境
- **异步处理**: 使用channel和协程实现高效并发
- **安全机制**: 认证、加密、流量限制等多重保障

---

## 相关文件索引

### 服务端核心
- 主逻辑: `server/server.go`
- 桥接器: `bridge/bridge.go`
- TCP隧道: `server/proxy/tcp.go`
- HTTP代理: `server/proxy/httpproxy/`
- UDP隧道: `server/proxy/udp.go`
- SOCKS5: `server/proxy/socks5.go`
- P2P: `server/proxy/p2p.go`

### 客户端核心
- 主逻辑: `client/client.go`
- 连接控制: `client/control.go`
- 本地服务: `client/local.go`
- P2P: `client/p2p.go`

### 公共库
- 多路复用: `lib/mux/`
- 连接封装: `lib/conn/`
- 加密模块: `lib/crypt/`
- 配置管理: `lib/file/`
- 通用工具: `lib/common/`
- 日志模块: `lib/logs/`

