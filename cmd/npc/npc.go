//go:build !sdk
// +build !sdk

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ccding/go-stun/stun"     // STUN 协议客户端，用于 NAT 类型检测
	"github.com/kardianos/service"       // 跨平台服务管理库
	"github.com/mycoool/nps/client"      // NPC 客户端核心逻辑
	"github.com/mycoool/nps/lib/common"  // 公共工具函数
	"github.com/mycoool/nps/lib/config"  // 配置相关
	"github.com/mycoool/nps/lib/crypt"   // 加密相关
	"github.com/mycoool/nps/lib/file"    // 文件操作相关
	"github.com/mycoool/nps/lib/install" // 安装相关
	"github.com/mycoool/nps/lib/logs"    // 日志相关
	"github.com/mycoool/nps/lib/mux"     // 多路复用相关
	"github.com/mycoool/nps/lib/version" // 版本管理

	goflag "flag"

	flag "github.com/spf13/pflag" // 命令行参数解析
)

// Config - 命令行参数配置
var (
	ver            = flag.BoolP("version", "v", false, "显示当前版本")
	serverAddr     = flag.StringP("server", "s", "", "服务器地址，支持多服务器 (ip1:port1,ip2:port2)")
	verifyKey      = flag.StringP("vkey", "k", "", "验证密钥 (例如: vkey1,vkey2)")
	connType       = flag.StringP("type", "t", "tcp", "与服务器的连接类型 (tcp|tls|kcp|quic|ws|wss)，支持多种连接类型 (例如: tcp,tls)")
	configPath     = flag.StringP("config", "c", "", "配置文件路径，支持多个配置文件 (path1,path2)")
	proxyUrl       = flag.String("proxy", "", "SOCKS5 代理 URL (例如: socks5://user:pass@127.0.0.1:9007)")
	localType      = flag.String("local_type", "p2p", "P2P 目标类型")
	localPort      = flag.Int("local_port", 2000, "P2P 本地监听端口")
	password       = flag.String("password", "", "P2P 密码")
	target         = flag.String("target", "", "P2P 目标地址")
	targetType     = flag.String("target_type", "all", "P2P 目标连接类型 (all|tcp|udp)")
	p2pType        = flag.String("p2p_type", "quic", "P2P 连接类型 (quic|kcp)")
	localProxy     = flag.Bool("local_proxy", false, "是否启用本地代理")
	fallbackSecret = flag.Bool("fallback_secret", true, "P2P 是否使用密钥回退")
	disableP2P     = flag.Bool("disable_p2p", false, "是否禁用 P2P 连接")
	registerTime   = flag.Int("time", 2, "注册时间（小时）")
	logType        = flag.String("log", "file", "日志输出模式 (stdout|file|both|off)")
	logLevel       = flag.String("log_level", "trace", "日志级别 (trace|debug|info|warn|error|fatal|panic|off)")
	logPath        = flag.String("log_path", "", "NPC 日志文件路径（空表示使用默认路径，'off' 表示禁用）")
	logMaxSize     = flag.Int("log_max_size", 5, "日志文件最大大小（MB），超过后轮转（0 表示不限制）")
	logMaxDays     = flag.Int("log_max_days", 7, "日志文件保留天数（0 表示不限制）")
	logMaxFiles    = flag.Int("log_max_files", 10, "最多保留的日志文件数量（0 表示不限制）")
	logCompress    = flag.Bool("log_compress", false, "是否压缩轮转后的日志文件")
	logColor       = flag.Bool("log_color", true, "控制台输出是否启用 ANSI 颜色")
	debug          = flag.Bool("debug", true, "是否启用调试模式")
	pprofAddr      = flag.String("pprof", "", "PProf 性能分析监听地址 (ip:port)")
	stunAddr       = flag.String("stun_addr", "stun.miwifi.com:3478", "STUN 服务器地址，用于 NAT 类型检测")
	protoVer       = flag.Int("proto_version", version.GetLatestIndex(), fmt.Sprintf("协议版本 (0-%d)", version.GetLatestIndex()))
	skipVerify     = flag.Bool("skip_verify", false, "是否跳过服务器证书验证")
	disconnectTime = flag.Int("disconnect_timeout", 60, "断开连接超时时间（秒）")
	keepAlive      = flag.Int("keepalive", 0, "KeepAlive 保活周期（秒）")
	p2pTime        = flag.Int("p2p_timeout", 5, "P2P 连接超时时间（秒）")
	dnsServer      = flag.String("dns_server", "8.8.8.8", "DNS 服务器地址")
	ntpServer      = flag.String("ntp_server", "", "NTP 时间同步服务器地址")
	ntpInterval    = flag.Int("ntp_interval", 5, "NTP 时间同步间隔（分钟）")
	tlsEnable      = flag.Bool("tls_enable", false, "是否启用 TLS（已弃用）")
	timezone       = flag.String("timezone", "", "时区设置（例如: Asia/Shanghai）")
	genTOTP        = flag.Bool("gen2fa", false, "生成 TOTP 密钥")
	getTOTP        = flag.String("get2fa", "", "获取 TOTP 动态验证码")
	autoReconnect  = flag.Bool("auto_reconnect", true, "是否自动重连")
)

// main - NPC 客户端主函数，程序入口点
// 负责：
// 1. 解析命令行参数
// 2. 处理各种子命令（status、register、nat、update 等）
// 3. 配置系统服务（install、start、stop 等）
// 4. 启动客户端核心逻辑
func main() {
	// 设置命令行参数标准化函数，将 "-" 和 "." 替换为 "_"
	flag.CommandLine.SetNormalizeFunc(func(f *flag.FlagSet, name string) flag.NormalizedName {
		name = strings.ReplaceAll(name, "-", "_")
		name = strings.ReplaceAll(name, ".", "_")
		return flag.NormalizedName(name)
	})
	// 标准化旧版长参数格式（单横线开头的长参数）
	normalizeLegacyLongFlags()
	flag.CommandLine.SortFlags = false                // 不对参数排序，保持参数顺序
	flag.CommandLine.SetInterspersed(true)            // 允许参数和标志混用
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine) // 添加标准库的 flag
	flag.Parse()

	// 获取命令行参数（非标志参数）
	args := flag.Args()
	var cmd string
	if len(args) > 0 {
		cmd = args[0]
	}

	// TOTP（基于时间的一次性密码）相关功能
	// 生成 TOTP 密钥
	if *genTOTP {
		crypt.PrintTOTPSecret()
		return
	}
	// 获取 TOTP 动态验证码
	if *getTOTP != "" {
		crypt.PrintTOTPCode(*getTOTP)
		return
	}
	// 显示版本信息
	if *ver {
		version.PrintVersion(*protoVer)
		return
	}

	// 设置客户端全局配置
	client.Ver = *protoVer                // 协议版本
	client.SkipTLSVerify = *skipVerify    // 是否跳过 TLS 验证
	client.DisableP2P = *disableP2P       // 是否禁用 P2P
	client.AutoReconnect = *autoReconnect // 是否自动重连
	crypt.SkipVerify = *skipVerify
	// 协议版本 2 以下默认跳过验证
	if *protoVer < 2 {
		crypt.SkipVerify = true
	}

	// 设置时区
	if err := common.SetTimezone(*timezone); err != nil {
		logs.Warn("Set timezone error %v", err)
	}

	// 配置日志系统
	configureLogging()

	// 设置自定义 DNS 服务器
	common.SetCustomDNS(*dnsServer)

	// 配置 NTP 时间同步
	common.SetNtpServer(*ntpServer)
	common.SetNtpInterval(time.Duration(*ntpInterval) * time.Minute)

	// 配置 KeepAlive 保活机制
	if *keepAlive > 0 {
		interval := time.Duration(*keepAlive) * time.Second
		client.QuicConfig.KeepAlivePeriod = interval // QUIC 协议保活周期
		mux.PingInterval = interval                  // 多路复用 Ping 间隔
	}

	// 配置 P2P 连接模式
	switch strings.ToLower(*p2pType) {
	case common.CONN_QUIC:
		client.P2PMode = common.CONN_QUIC
	case common.CONN_KCP:
		client.P2PMode = common.CONN_KCP
	default:
	}

	// 初始化系统服务配置
	options := make(service.KeyValue)
	svcConfig := &service.Config{
		Name:        "Npc",
		DisplayName: "nps内网穿透客户端",
		Description: "一款轻量级、功能强大的内网穿透代理服务器。支持tcp、udp流量转发，支持内网http代理、内网socks5代理，同时支持snappy压缩、站点保护、加密传输、多路复用、header修改等。支持web图形化管理，集成多用户模式。",
		Option:      options,
	}

	// 非 Windows 系统添加服务依赖（Linux/Unix 特有配置）
	if !common.IsWindows() {
		svcConfig.Dependencies = []string{
			"Requires=network.target",
			"After=network-online.target syslog.target"}
		svcConfig.Option["SystemdScript"] = install.SystemdScript // Systemd 服务脚本
		svcConfig.Option["SysvScript"] = install.SysvScript       // SysV 服务脚本
	}

	// 配置服务启动参数（过滤掉命令本身和服务控制命令）
	for _, v := range os.Args[1:] {
		switch v {
		case "install", "start", "stop", "uninstall", "restart",
			"status", "register", "nat", "update":
			continue
		}
		if !strings.Contains(v, "-service=") && !strings.Contains(v, "-debug=") {
			svcConfig.Arguments = append(svcConfig.Arguments, v)
		}
	}
	svcConfig.Arguments = append(svcConfig.Arguments, "-debug=false") // 服务模式默认关闭调试

	// 创建服务实例
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prg := NewNpc(ctx)
	s, err := service.New(prg, svcConfig)
	if err != nil {
		// 服务创建失败（可能在不支持服务的环境中运行），直接运行
		logs.Error("service function disabled %v", err)
		run(ctx, cancel)
		// 阻塞主线程不退出
		wg := sync.WaitGroup{}
		wg.Add(1)
		wg.Wait()
		return
	}

	// 处理各种子命令
	switch cmd {
	case "status":
		// 查看客户端状态
		client.GetTaskStatus(*serverAddr, *verifyKey, *connType, *proxyUrl)
		return
	case "register":
		// 注册本地 IP 到服务器
		client.RegisterLocalIp(*serverAddr, *verifyKey, *connType, *proxyUrl, *registerTime)
		return
	case "update":
		// 更新 NPC 客户端
		install.UpdateNpc()
		return
	case "nat":
		// 检测 NAT 类型（使用 STUN 协议）
		c := stun.NewClient()
		c.SetServerAddr(*stunAddr)
		fmt.Println("STUN Server:", *stunAddr)
		nat, host, err := c.Discover()
		if err != nil {
			logs.Error("Error: %v", err)
			return
		}
		fmt.Println("NAT Type:", nat)
		if host != nil {
			fmt.Println("External IP Family:", host.Family())
			fmt.Println("External IP:", host.IP())
			fmt.Println("External Port:", host.Port())
		}
		os.Exit(0)
	case "start", "stop", "restart":
		// 服务控制命令
		// 支持 busyBox 和 sysV（OpenWrt 等嵌入式系统）
		if service.Platform() == "unix-systemv" {
			logs.Info("unix-systemv service")
			cmd := exec.Command("/etc/init.d/"+svcConfig.Name, os.Args[1])
			if err := cmd.Run(); err != nil {
				logs.Error("%v", err)
			}
			return
		}
		if err := service.Control(s, os.Args[1]); err != nil {
			logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
		}
		return
	case "install":
		// 安装为系统服务
		_ = service.Control(s, "stop")
		_ = service.Control(s, "uninstall")
		install.InstallNpc()
		if err := service.Control(s, os.Args[1]); err != nil {
			logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
		}
		// 创建 SysV 启动链接
		if service.Platform() == "unix-systemv" {
			logs.Info("unix-systemv service")
			confPath := "/etc/init.d/" + svcConfig.Name
			_ = os.Symlink(confPath, "/etc/rc.d/S90"+svcConfig.Name)
			_ = os.Symlink(confPath, "/etc/rc.d/K02"+svcConfig.Name)
		}
		return
	case "uninstall":
		// 卸载系统服务
		if err := service.Control(s, os.Args[1]); err != nil {
			logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
		}
		if service.Platform() == "unix-systemv" {
			logs.Info("unix-systemv service")
			_ = os.Remove("/etc/rc.d/S90" + svcConfig.Name)
			_ = os.Remove("/etc/rc.d/K02" + svcConfig.Name)
		}
		return
	}
	// 无子命令，正常启动服务
	_ = s.Run()
}

// normalizeLegacyLongFlags - 标准化旧版长参数格式
// 将单横线开头的长参数（如 -server=xxx）转换为双横线格式（--server=xxx）
// 这样可以兼容旧版的使用习惯，同时保持与新版参数解析的一致性
func normalizeLegacyLongFlags() {
	norm := func(s string) string {
		s = strings.ReplaceAll(s, "-", "_")
		s = strings.ReplaceAll(s, ".", "_")
		return s
	}
	// 获取所有已定义的参数名称
	defined := map[string]struct{}{}
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		defined[norm(f.Name)] = struct{}{}
	})
	if len(os.Args) <= 1 {
		return
	}
	out := make([]string, 0, len(os.Args))
	out = append(out, os.Args[0])
	// 遍历命令行参数
	for _, a := range os.Args[1:] {
		// 检查是否是单横线长参数（例如 -server=xxx）
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 2 {
			s := a[1:]
			name, val := s, ""
			if i := strings.IndexByte(s, '='); i >= 0 {
				name, val = s[:i], s[i:]
			}
			// 如果是已定义的参数，转换为双横线格式
			if _, ok := defined[norm(name)]; ok {
				a = "--" + name + val
			}
		}
		out = append(out, a)
	}
	os.Args = out
}

// configureLogging - 配置日志系统
// 根据用户参数设置日志输出模式、级别、路径等
func configureLogging() {
	// 将 "false" 标准化为 "off"
	if strings.EqualFold(*logType, "false") {
		*logType = "off"
	}
	// 调试模式下，自动调整日志配置
	if *debug && *logType != "off" {
		if *logType != "both" {
			*logType = "stdout" // 调试模式默认输出到控制台
		}
		*logLevel = "trace" // 调试模式使用最详细的日志级别
	}
	// 设置日志文件路径
	if *logPath == "" || strings.EqualFold(*logPath, "on") || strings.EqualFold(*logPath, "true") {
		*logPath = common.GetNpcLogPath() // 使用默认日志路径
	}
	// 如果不是绝对路径，则拼接运行目录
	if !filepath.IsAbs(*logPath) {
		*logPath = filepath.Join(common.GetRunPath(), *logPath)
	}
	// Windows 系统需要转义反斜杠
	if common.IsWindows() {
		*logPath = strings.Replace(*logPath, "\\", "\\\\", -1)
	}
	// 初始化日志系统
	logs.Init(*logType, *logLevel, *logPath, *logMaxSize, *logMaxFiles, *logMaxDays, *logCompress, *logColor)
}

// Npc - NPC 服务结构体
// 实现了 service.Service 接口，用于系统服务管理
type Npc struct {
	ctx    context.Context    // 上下文，用于优雅退出
	cancel context.CancelFunc // 取消函数，用于通知所有协程退出
	exit   chan struct{}      // 退出通道，用于接收退出信号
}

// NewNpc - 创建新的 NPC 服务实例
// pCtx: 父上下文
func NewNpc(pCtx context.Context) *Npc {
	ctx, cancel := context.WithCancel(pCtx)
	return &Npc{
		ctx:    ctx,
		exit:   make(chan struct{}),
		cancel: cancel,
	}
}

// Start - 启动 NPC 服务（实现 service.Service 接口）
// 这是服务管理器调用的启动方法
func (p *Npc) Start(_ service.Service) error {
	go func() {
		if err := p.run(); err != nil {
			logs.Error("npc run error: %v", err)
		}
	}() // 在协程中运行主逻辑
	return nil
}

// Stop - 停止 NPC 服务（实现 service.Service 接口）
// 这是服务管理器调用的停止方法
func (p *Npc) Stop(_ service.Service) error {
	close(p.exit) // 发送退出信号
	p.cancel()    // 取消上下文
	if service.Interactive() {
		os.Exit(0) // 交互模式下直接退出进程
	}
	return nil
}

// run - NPC 主运行逻辑
// 包含 panic 恢复机制，确保程序崩溃时能记录堆栈信息
func (p *Npc) run() error {
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10 // 64KB
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)] // 获取堆栈信息
			logs.Warn("npc: panic serving %v: %s", err, buf)
		}
	}()
	run(p.ctx, p.cancel) // 调用主业务逻辑
	<-p.exit             // 等待退出信号
	logs.Warn("stop...")
	return nil
}

// run - NPC 主运行逻辑
// 负责启动各种连接模式：
// 1. P2P 模式（通过密码连接）
// 2. 命令行模式（通过 -s, -k 参数）
// 3. 配置文件模式
// 支持多服务器、多连接的并发连接
// ctx: 上下文，用于优雅退出
// cancel: 取消函数，用于通知所有协程退出
func run(ctx context.Context, cancel context.CancelFunc) {
	// 初始化 PProf 性能分析工具
	common.InitPProfByAddr(*pprofAddr)

	// 如果启用了旧版 TLS 配置，则将连接类型设置为 tls
	if *tlsEnable {
		*connType = "tls"
	}

	// P2P 模式：通过密码直接连接
	if *password != "" {
		logs.Info("the version of client is %s, the core version of client is %s", version.VERSION, version.GetVersion(*protoVer))
		common.SyncTime() // 同步时间
		// 配置通用配置
		commonConfig := new(config.CommonConfig)
		commonConfig.Server = *serverAddr
		commonConfig.VKey = *verifyKey
		commonConfig.Tp = strings.ToLower(*connType)
		// 配置本地服务器
		localServer := new(config.LocalServer)
		localServer.Type = strings.ToLower(*localType)
		localServer.Password = *password
		localServer.Target = *target
		localServer.TargetType = strings.ToLower(*targetType)
		localServer.Port = *localPort
		localServer.Fallback = *fallbackSecret
		localServer.LocalProxy = *localProxy
		commonConfig.Client = new(file.Client)
		commonConfig.Client.Cnf = new(file.Config)
		commonConfig.DisconnectTime = *p2pTime
		// 创建 P2P 管理器并启动
		p2pm := client.NewP2PManager(ctx, cancel, commonConfig)
		go p2pm.StartLocalServer(localServer)
		return
	}

	// 从环境变量读取配置（支持容器化部署）
	env := common.GetEnvMap()
	if *serverAddr == "" {
		*serverAddr = env["NPC_SERVER_ADDR"]
	}
	if *verifyKey == "" {
		*verifyKey = env["NPC_SERVER_VKEY"]
	}
	if *configPath == "" {
		*configPath = env["NPC_CONFIG_PATH"]
	}

	// 判断是否使用命令行参数模式（需要同时提供服务器地址和验证密钥）
	hasCommand := *verifyKey != "" && *serverAddr != ""

	// 命令行模式：通过 -s 和 -k 参数启动连接
	if hasCommand {
		logs.Info("the version of client is %s, the core version of client is %s", version.VERSION, version.GetVersion(*protoVer))
		common.SyncTime() // 同步时间
		// 标准化中文标点符号
		*serverAddr = strings.ReplaceAll(*serverAddr, "，", ",")
		*serverAddr = strings.ReplaceAll(*serverAddr, "：", ":")
		*verifyKey = strings.ReplaceAll(*verifyKey, "，", ",")
		*connType = strings.ReplaceAll(*connType, "，", ",")

		// 解析多个服务器地址、密钥和连接类型
		serverAddrs := strings.Split(*serverAddr, ",")
		verifyKeys := strings.Split(*verifyKey, ",")
		connTypes := strings.Split(*connType, ",")

		// 过滤空值
		serverAddrs = common.HandleArrEmptyVal(serverAddrs)
		verifyKeys = common.HandleArrEmptyVal(verifyKeys)
		connTypes = common.HandleArrEmptyVal(connTypes)

		// 如果没有指定连接类型，默认使用 tcp
		if len(connTypes) == 0 {
			connTypes = append(connTypes, "tcp")
		}

		// 检查必要参数
		if len(serverAddrs) == 0 || len(verifyKeys) == 0 || serverAddrs[0] == "" || verifyKeys[0] == "" {
			logs.Error("serverAddr or verifyKey cannot be empty")
			os.Exit(1)
		}

		// 扩展数组长度，使三个数组长度一致
		maxLength := common.ExtendArrs(&serverAddrs, &verifyKeys, &connTypes)
		// 为每个服务器连接启动一个协程
		for i := 0; i < maxLength; i++ {
			serverAddr := serverAddrs[i]
			verifyKey := verifyKeys[i]
			connType := connTypes[i]
			connType = strings.ToLower(connType)

			go func() {
				for {
					logs.Info("Start server: %s vkey: %s type: %s", serverAddr, verifyKey, connType)
					// 创建 RPC 客户端并启动连接
					client.NewRPClient(serverAddr, verifyKey, connType, *proxyUrl, "", nil, *disconnectTime, nil).Start(ctx)
					// 连接关闭后的处理
					if *autoReconnect {
						logs.Info("Client closed! It will be reconnected in five seconds")
						time.Sleep(time.Second * 5) // 等待 5 秒后重连
					} else {
						logs.Info("Client closed!")
						cancel()   // 取消上下文
						os.Exit(1) // 退出程序
						return
					}
				}
			}()
		}
	}

	// 配置文件模式：从配置文件读取配置并启动
	if *configPath != "" || !hasCommand {
		// 如果没有指定配置文件路径，使用默认路径
		if *configPath == "" {
			*configPath = common.GetConfigPath()
		}

		// 解析多个配置文件路径
		configPaths := strings.Split(*configPath, ",")
		for i := range configPaths {
			configPaths[i] = strings.TrimSpace(configPaths[i])
		}

		// 为每个配置文件启动一个客户端
		for _, path := range configPaths {
			go client.StartFromFile(ctx, cancel, path)
		}
	}
}
