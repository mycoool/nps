package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego"                   // Beego Web 框架
	"github.com/kardianos/service"             // 跨平台服务管理库
	"github.com/mycoool/nps/bridge"            // 桥接服务（客户端与服务器之间的连接）
	"github.com/mycoool/nps/lib/common"        // 公共工具函数
	"github.com/mycoool/nps/lib/crypt"         // 加密相关
	"github.com/mycoool/nps/lib/daemon"        // 守护进程
	"github.com/mycoool/nps/lib/file"          // 文件操作相关
	"github.com/mycoool/nps/lib/install"       // 安装相关
	"github.com/mycoool/nps/lib/logs"          // 日志相关
	"github.com/mycoool/nps/lib/version"       // 版本管理
	"github.com/mycoool/nps/server"            // 服务器核心逻辑
	"github.com/mycoool/nps/server/connection" // 连接管理
	"github.com/mycoool/nps/server/tool"       // 服务器工具
	"github.com/mycoool/nps/web/routers"       // Web 路由

	goflag "flag"

	flag "github.com/spf13/pflag" // 命令行参数解析
)

var (
	logLevel string // 日志级别变量
	confPath = flag.StringP("conf_path", "c", "", "指定配置文件路径")
	ver      = flag.BoolP("version", "v", false, "显示当前版本信息")
	genTOTP  = flag.Bool("gen2fa", false, "生成 TOTP 密钥")
	getTOTP  = flag.String("get2fa", "", "获取 TOTP 动态验证码")
)

// main - NPS 服务器主函数，程序入口点
// 负责：
// 1. 解析命令行参数
// 2. 加载配置文件
// 3. 配置日志、时区、DNS、PProf 等
// 4. 处理各种子命令（install、start、stop、update 等）
// 5. 启动服务器核心逻辑
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
		version.PrintVersion(version.GetLatestIndex())
		return
	}

	// 设置配置文件路径（如果通过命令行参数指定）
	if cp := strings.TrimSpace(*confPath); cp != "" {
		common.ConfPath = cp
	}

	// 加载配置文件（优先从运行目录加载，失败则从安装目录加载）
	if err := beego.LoadAppConfig("ini", filepath.Join(common.GetRunPath(), "conf", "nps.conf")); err != nil {
		log.Println("load config file error", err.Error())
		if err := beego.LoadAppConfig("ini", filepath.Join(common.GetAppPath(), "conf", "nps.conf")); err != nil {
			log.Fatalln("load config file error", err.Error())
		}
	}

	// 初始化 PProf 性能分析工具
	pprofIp := beego.AppConfig.String("pprof_ip")
	pprofPort := beego.AppConfig.String("pprof_port")
	pprofAddr := common.BuildAddress(pprofIp, pprofPort)
	common.InitPProfByAddr(pprofAddr)

	// 设置时区
	err := common.SetTimezone(beego.AppConfig.String("timezone"))
	if err != nil {
		logs.Warn("Set timezone error %v", err)
	}

	// 设置自定义 DNS 服务器
	common.SetCustomDNS(beego.AppConfig.String("dns_server"))

	// 从配置文件读取日志配置
	logType := beego.AppConfig.DefaultString("log", "stdout")
	logLevel = beego.AppConfig.DefaultString("log_level", "trace")
	logPath := beego.AppConfig.String("log_path")
	// 设置日志文件路径
	if logPath == "" || strings.EqualFold(logPath, "on") || strings.EqualFold(logPath, "true") {
		logPath = common.GetLogPath()
	}
	// 处理日志路径为绝对路径
	if !strings.EqualFold(logPath, "off") && !strings.EqualFold(logPath, "false") && !strings.EqualFold(logPath, "docker") && logPath != "/dev/null" {
		if !filepath.IsAbs(logPath) {
			logPath = filepath.Join(common.GetRunPath(), logPath)
		}
		if common.IsWindows() {
			logPath = strings.Replace(logPath, "\\", "\\\\", -1)
		}
	}
	// 日志轮转配置
	logMaxFiles := beego.AppConfig.DefaultInt("log_max_files", 30)
	logMaxDays := beego.AppConfig.DefaultInt("log_max_days", 30)
	logMaxSize := beego.AppConfig.DefaultInt("log_max_size", 5)
	logCompress := beego.AppConfig.DefaultBool("log_compress", false)
	logColor := beego.AppConfig.DefaultBool("log_color", true)

	// 初始化系统服务配置
	options := make(service.KeyValue)
	svcConfig := &service.Config{
		Name:        "Nps",
		DisplayName: "nps内网穿透代理服务器",
		Description: "一款轻量级、功能强大的内网穿透代理服务器。支持tcp、udp流量转发，支持内网http代理、内网socks5代理，同时支持snappy压缩、站点保护、加密传输、多路复用、header修改等。支持web图形化管理，集成多用户模式。",
		Option:      options,
	}

	// 配置服务启动参数（过滤掉服务控制命令）
	for _, v := range os.Args[1:] {
		switch v {
		case "install", "start", "stop", "uninstall", "restart":
			continue
		}
		svcConfig.Arguments = append(svcConfig.Arguments, v)
	}

	// 添加 "service" 参数，表示这是服务模式运行
	svcConfig.Arguments = append(svcConfig.Arguments, "service")
	// 服务模式下，默认日志输出到文件
	if len(os.Args) > 1 && os.Args[1] == "service" && !strings.EqualFold(logType, "off") && !strings.EqualFold(logType, "both") {
		logType = "file"
	}

	// 初始化日志系统
	logs.Init(logType, logLevel, logPath, logMaxSize, logMaxFiles, logMaxDays, logCompress, logColor)

	// 非 Windows 系统添加服务依赖（Linux/Unix 特有配置）
	if !common.IsWindows() {
		svcConfig.Dependencies = []string{
			"Requires=network.target",
			"After=network-online.target syslog.target"}
		svcConfig.Option["SystemdScript"] = install.SystemdScript // Systemd 服务脚本
		svcConfig.Option["SysvScript"] = install.SysvScript       // SysV 服务脚本
	}

	// 创建服务实例
	prg := &nps{}
	prg.exit = make(chan struct{})
	s, err := service.New(prg, svcConfig)
	if err != nil {
		// 服务创建失败（可能在不支持服务的环境中运行），直接运行
		logs.Error("service function disabled %v", err)
		run()
		// 阻塞主线程不退出
		wg := sync.WaitGroup{}
		wg.Add(1)
		wg.Wait()
		return
	}

	// 处理各种子命令
	if cmd != "" && cmd != "service" {
		switch cmd {
		case "reload":
			// 重新加载配置（守护进程模式）
			daemon.InitDaemon("nps", common.GetRunPath(), common.GetTmpPath())
			return
		case "install":
			// 安装为系统服务
			_ = service.Control(s, "stop")
			_ = service.Control(s, "uninstall")

			binPath := install.InstallNps()
			svcConfig.Executable = binPath
			s, err := service.New(prg, svcConfig)
			if err != nil {
				logs.Error("%v", err)
				return
			}
			err = service.Control(s, cmd)
			if err != nil {
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
		case "start", "restart", "stop":
			// 服务控制命令
			if service.Platform() == "unix-systemv" {
				logs.Info("unix-systemv service")
				c := exec.Command("/etc/init.d/"+svcConfig.Name, cmd)
				if err := c.Run(); err != nil {
					logs.Error("%v", err)
				}
				return
			}
			err := service.Control(s, cmd)
			if err != nil {
				logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
			}
			return
		case "uninstall":
			// 卸载系统服务
			err := service.Control(s, cmd)
			if err != nil {
				logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
			}
			if service.Platform() == "unix-systemv" {
				logs.Info("unix-systemv service")
				_ = os.Remove("/etc/rc.d/S90" + svcConfig.Name)
				_ = os.Remove("/etc/rc.d/K02" + svcConfig.Name)
			}
			return
		case "update":
			// 更新 NPS 服务器
			install.UpdateNps()
			return
		}
	}
	// 无子命令，正常启动服务
	_ = s.Run()
}

// normalizeLegacyLongFlags - 标准化旧版长参数格式
// 将单横线开头的长参数（如 -conf_path=xxx）转换为双横线格式（--conf_path=xxx）
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
		// 检查是否是单横线长参数（例如 -conf_path=xxx）
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

// nps - NPS 服务结构体
// 实现了 service.Service 接口，用于系统服务管理
type nps struct {
	exit chan struct{} // 退出通道，用于接收退出信号
}

// Start - 启动 NPS 服务（实现 service.Service 接口）
// 这是服务管理器调用的启动方法
func (p *nps) Start(s service.Service) error {
	_, _ = s.Status()
	go func() {
		if err := p.run(); err != nil {
			logs.Error("nps run error: %v", err)
		}
	}() // 在协程中运行主逻辑
	return nil
}

// Stop - 停止 NPS 服务（实现 service.Service 接口）
// 这是服务管理器调用的停止方法
func (p *nps) Stop(s service.Service) error {
	_, _ = s.Status()
	close(p.exit) // 发送退出信号
	if service.Interactive() {
		os.Exit(0) // 交互模式下直接退出进程
	}
	return nil
}

// run - NPS 主运行逻辑
// 包含 panic 恢复机制，确保程序崩溃时能记录堆栈信息
func (p *nps) run() error {
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10 // 64KB
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)] // 获取堆栈信息
			logs.Warn("nps: panic serving %v: %s", err, buf)
		}
	}()
	run()    // 调用主业务逻辑
	<-p.exit // 等待退出信号
	logs.Warn("stop...")
	return nil
}

// run - NPS 服务器主运行逻辑
// 负责：
// 1. 初始化 Web 路由和隧道配置
// 2. 配置安全模式和客户端选择模式
// 3. 配置 NTP 时间同步
// 4. 初始化 TLS 证书
// 5. 初始化系统信息和允许端口
// 6. 配置桥接服务（TCP/TLS/KCP/QUIC/WS/WSS）
// 7. 启动服务器
func run() {
	// 初始化 Web 路由（管理后台接口）
	routers.Init()

	// 创建隧道任务配置
	task := &file.Tunnel{
		Mode: "webServer",
	}

	// 设置安全模式（启用后会对客户端进行更严格的验证）
	if beego.AppConfig.DefaultBool("secure_mode", false) {
		bridge.ServerSecureMode = true
	}

	// 打印配置路径和版本信息
	logs.Info("the config path is: %s", common.GetRunPath())
	logs.Info("the version of server is %s, allow client core version to be %s", version.VERSION, version.GetMinVersion(bridge.ServerSecureMode))

	// 设置客户端选择模式（负载均衡策略）
	_ = bridge.SetClientSelectMode(beego.AppConfig.DefaultString("bridge_select_mode", ""))

	// 配置 NTP 时间同步
	ntpServer := beego.AppConfig.DefaultString("ntp_server", "")
	ntpInterval := beego.AppConfig.DefaultInt("ntp_interval", 5)
	common.SetNtpServer(ntpServer)
	common.SetNtpInterval(time.Duration(ntpInterval) * time.Minute)
	go common.SyncTime() // 在协程中启动时间同步

	// 初始化连接服务（管理客户端连接）
	connection.InitConnectionService()

	// 加载 TLS 证书（用于加密通信）
	cert, ok := common.LoadCert(beego.AppConfig.String("bridge_cert_file"), beego.AppConfig.String("bridge_key_file"))
	if !ok {
		logs.Info("Using randomly generated certificate.")
	}
	crypt.InitTls(cert)

	// 初始化允许的端口和系统信息
	tool.InitAllowPort()
	tool.StartSystemInfo()

	// 获取断开连接超时时间
	timeout := beego.AppConfig.DefaultInt("disconnect_timeout", 60)
	bridgePort := connection.BridgePort

	// 配置桥接服务类型（支持 TCP、UDP、Both）
	bridgeType := beego.AppConfig.DefaultString("bridge_type", "both")

	// 配置各种传输协议
	// KCP 协议（基于 UDP 的可靠传输）
	bridge.ServerKcpEnable = beego.AppConfig.DefaultBool("kcp_enable", true) && connection.BridgeKcpPort != 0 && (bridgeType == "kcp" || bridgeType == "udp" || bridgeType == "both")
	// QUIC 协议（基于 UDP 的 HTTP/3 传输）
	bridge.ServerQuicEnable = beego.AppConfig.DefaultBool("quic_enable", true) && connection.BridgeQuicPort != 0 && (bridgeType == "quic" || bridgeType == "udp" || bridgeType == "both")

	// 如果是 both 模式，默认使用 TCP
	if bridgeType == "both" {
		bridgeType = "tcp"
	}

	// TCP 协议
	bridge.ServerTcpEnable = beego.AppConfig.DefaultBool("tcp_enable", true) && connection.BridgeTcpPort != 0 && bridgeType == "tcp"
	// TLS 协议（TCP + 加密）
	bridge.ServerTlsEnable = beego.AppConfig.DefaultBool("tls_enable", true) && connection.BridgeTlsPort != 0 && bridgeType == "tcp"
	// WebSocket 协议（基于 TCP 的全双工通信）
	bridge.ServerWsEnable = beego.AppConfig.DefaultBool("ws_enable", true) && connection.BridgeWsPort != 0 && connection.BridgePath != "" && bridgeType == "tcp"
	// Secure WebSocket 协议（WebSocket + TLS）
	bridge.ServerWssEnable = beego.AppConfig.DefaultBool("wss_enable", true) && connection.BridgeWssPort != 0 && connection.BridgePath != "" && bridgeType == "tcp"

	// 启动服务器（在协程中运行）
	go server.StartNewServer(bridgePort, task, bridgeType, timeout)
}
