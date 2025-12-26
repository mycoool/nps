# NPS 内网穿透 (全修)

[![GitHub Stars](https://img.shields.io/github/stars/mycoool/nps.svg)](https://github.com/mycoool/nps)
[![GitHub Forks](https://img.shields.io/github/forks/mycoool/nps.svg)](https://github.com/mycoool/nps)
[![Release](https://github.com/mycoool/nps/workflows/Release/badge.svg)](https://github.com/mycoool/nps/actions)
[![GitHub All Releases](https://img.shields.io/github/downloads/mycoool/nps/total)](https://github.com/mycoool/nps/releases)

> 由于 GitHub 限制浏览器语言为中文（Accept-Language=zh-CN) 访问 *.githubusercontent.com ，图标可能无法正常显示。

- [English](https://github.com/mycoool/nps/blob/master/README_en.md)

---

## 简介

NPS 是一款轻量高效的内网穿透代理服务器，支持多种协议（TCP、UDP、HTTP、HTTPS、SOCKS5 等）转发。它提供直观的 Web 管理界面，使得内网资源能安全、便捷地在外网访问，同时满足多种复杂场景的需求。

由于[NPS](https://github.com/ehang-io/nps)停更已久，本仓库整合社区更新二次开发而来。

- **提问前请先查阅：**  [文档](https://d-jy.net/docs/nps/) 与 [Issues](https://github.com/mycoool/nps/issues)
- **欢迎参与：**  提交 PR、反馈问题或建议，共同推动项目发展。
- **讨论交流：**  加入 [Telegram 交流群](https://t.me/npsdev) 与其他用户交流经验。
- **Android：**  [mycoool/npsclient](https://github.com/mycoool/npsclient)
- **OpenWrt：**  [mycoool/nps-openwrt](https://github.com/mycoool/nps-openwrt)

---

## 主要特性

- **多协议支持**  
  TCP/UDP 转发、HTTP/HTTPS 转发、HTTP/SOCKS5 代理、P2P 模式、Proxy Protocol支持、HTTP/3支持等，满足各种内网访问场景。

- **跨平台部署**  
  支持 Linux、Windows 等主流平台，可轻松安装为系统服务。

- **Web 管理界面**  
  实时监控流量、连接情况以及客户端状态，操作简单直观。

- **安全与扩展**  
  内置加密传输、流量限制、到期限制、证书管理续签等多重功能，保障数据安全。

- **多连接协议**  
  支持 TCP、KCP、TLS、QUIC、WS、WSS 协议连接服务器。

---

## 安装与使用

更多详细配置请参考 [文档](https://d-jy.net/docs/nps/)（部分内容可能未更新）。

### [Android](https://github.com/mycoool/npsclient) | [OpenWrt](https://github.com/mycoool/nps-openwrt)

### Docker 部署

***DockerHub***： [NPS](https://hub.docker.com/r/mycoool/nps) [NPC](https://hub.docker.com/r/mycoool/npc)

***GHCR***： [NPS](https://github.com/mycoool/nps/pkgs/container/nps) [NPC](https://github.com/mycoool/nps/pkgs/container/npc)

> 有真实IP获取需求可配合 [mmproxy](https://github.com/djylb/mmproxy-docker) 使用。例如：SSH

#### NPS 服务端
```bash
docker pull mycoool/nps
docker run -d --restart=always --name nps --net=host -v $(pwd)/conf:/conf -v /etc/localtime:/etc/localtime:ro mycoool/nps
```

#### NPC 客户端
```bash
docker pull mycoool/npc
docker run -d --restart=always --name npc --net=host mycoool/npc -server=xxx:123,yyy:456 -vkey=key1,key2 -type=tls,tcp -log=off
```

### 服务端安装

#### Linux
```bash
# 安装（默认配置路径：/etc/nps/；二进制文件路径：/usr/bin/）
wget -qO- https://fastly.jsdelivr.net/gh/djylb/nps@master/install.sh | sudo sh -s nps
nps install
nps start|stop|restart|uninstall

# 更新
nps update && nps restart
```

#### Windows
> Windows 7 用户请使用 old 结尾版本 [64](https://github.com/mycoool/nps/releases/latest/download/windows_amd64_server_old.tar.gz) / [32](https://github.com/mycoool/nps/releases/latest/download/windows_386_server_old.tar.gz) （需要手动更新）
```powershell
.\nps.exe install
.\nps.exe start|stop|restart|uninstall

# 更新
.\nps.exe stop
.\nps-update.exe update
.\nps.exe start
```

### 客户端安装

#### Linux
```bash
wget -qO- https://fastly.jsdelivr.net/gh/djylb/nps@master/install.sh | sudo sh -s npc
/usr/bin/npc install -server=xxx:123,yyy:456 -vkey=xxx,yyy -type=tls -log=off
npc start|stop|restart|uninstall

# 更新
npc update && npc restart
```

#### Windows
> Windows 7 用户请使用 old 结尾版本 [64](https://github.com/mycoool/nps/releases/latest/download/windows_amd64_client_old.tar.gz) / [32](https://github.com/mycoool/nps/releases/latest/download/windows_386_client_old.tar.gz) （需要手动更新）
```powershell
.\npc.exe install -server="xxx:123,yyy:456" -vkey="xxx,yyy" -type="tls,tcp" -log="off"
.\npc.exe start|stop|restart|uninstall

# 更新
.\npc.exe stop
.\npc-update.exe update
.\npc.exe start
```

> **提示：** 客户端支持同时连接多个服务器，示例：  
> `npc -server=xxx:123,yyy:456,zzz:789 -vkey=key1,key2,key3 -type=tcp,tls`  
> 这里 `xxx:123` 使用 tcp, `yyy:456` 和 `zzz:789` 使用tls

> 如需连接旧版本服务器请添加 `-proto_version=0`

---

## 更新日志

### DEV

- **Main**
  - 待定，优先修BUG，新功能随缘更新

### Stable

- **v0.29.16 (2025-06-03)**
  - 修复DockerHub镜像构建失败
  - 调整界面配色

- **v0.29.12 (2025-05-28)**
  - 修复指定路径后验证码不显示
  - 修复域名转发 521 错误返回

- **v0.29.11 (2025-05-27)**
  - 避免每次TLS重新握手
  - 支持自动申请SSL证书 [#54](https://github.com/mycoool/nps/issues/54)
  - 调整域名转发匹配逻辑
  - 调整掉线检测逻辑

- **v0.29.10 (2025-05-26)**
  - 修复域名转发重复判断逻辑

- **v0.29.9 (2025-05-25)**
  - 重写数据库，性能优化至 O(1) 级别
  - 重写HTTPS模块，支持高并发
  - 重写证书缓存，支持懒加载、LRU

- **v0.29.8 (2025-05-25)**
  - 域名转发支持路径重写
  - 健康检查支持HTTPS

- **v0.29.7 (2025-05-24)**
  - 允许多客户端使用相同密钥连接 （仅最后连接的客户端生效）
  - 支持客户端断连后自动切换
  - 优化服务端资源释放

- **v0.29.6 (2025-05-24)**
  - 重写P2P服务端代码
  - 优化服务端性能
  - 优化局域网下P2P联通能力
  - 优化P2P断线重连
  - 减少默认P2P超时检测时间

- **v0.29.5 (2025-05-23)**
  - 清空客户端流量时同时清空对应隧道流量
  - 仪表盘显示内容自动刷新
  - 优化客户端性能
  - 文件模式支持WebDav（仅允许通过npc配置文件设置）
  - 优化配置文件读取

- **v0.29.4 (2025-05-20)**
  - 登录失败时不刷新页面
  - 登录失败时自动刷新验证码图片

- **v0.29.3 (2025-05-20)**
  - 客户端参数缺失端口时使用默认端口
  - 调整仪表盘显示内容 [#16](https://github.com/mycoool/nps/issues/16)
  - 修复英文翻译错误

- **v0.29.2 (2025-05-19)**
  - 退出登录按钮同时清空页面缓存
  - 登录注册页面密码使用公私钥加密传输
  - 修改注册页面配色

- **v0.29.1 (2025-05-19)**
  - 修复文字错误
  - 完善页面翻译
  - 调整混合代理页面状态为按钮
  - 网页提示命令自动选择协议
  - 调整模式显示
  - 修复XSS漏洞
  - 对齐网页文字和图标
  - 优化移动设备页面显示
  - TCP列表状态图标可点击访问网页
  - 调整列表显示题目（在右上角配置）
  - 隧道页面点击客户端ID复制vkey
    
- **v0.29.0 (2025-05-19)**
  - 合并HTTP代理和Socks5代理为混合代理
  - 美化Web界面 （参考 [#76](https://github.com/mycoool/nps/issues/76) 感谢 [arch3rPro](https://github.com/arch3rPro)）
  - 支持明暗主题切换
  - 修复注册验证码校验
  - 优化TCP释放逻辑
  - 优化域名转发请求头插入逻辑
  - 登录支持TOTP验证登录 (nps.conf 新增 `totp_secret` 配置)
  - nps、npc 支持 `-gen2fa` 参数生成两步验证密钥
  - nps、npc 支持 `-get2fa=<密钥>` 参数获取登录验证码 （也可以用APP管理）
  - 记录客户端连接桥接类型
  - 调整管理页面展示内容
  - 添加客户端流量重置按钮
  - 列表页面允许直接点击清空元素
  - 混合代理允许直接点击状态控制开关
  - 调整页面配色

- **v0.28.3 (2025-05-16)**
  - 优化并发读写
  - 延长时间校验窗口
  - 完善服务端日志输出
  - 重写HTTP正向代理
  - 支持同一端口监听HTTP/Socks5代理 [#56](https://github.com/mycoool/nps/issues/56)

- **v0.28.2 (2025-05-15)**
  - 修复HTTP正向代理 [#75](https://github.com/mycoool/nps/issues/75)

- **v0.28.1 (2025-05-15)**
  - 客户端加密校验证书

- **v0.28.0 (2025-05-15)**
  - TLS、WSS 默认校验证书 （支持自签名证书）
  - 防重放攻击、中间人攻击等 （建议使用TLS、WSS）
  - 优化域名解析速度

- **v0.27.0 (2025-05-14)**
  - 启用隧道添加端口检查 [#74](https://github.com/mycoool/nps/issues/74)
  - NPS添加`secure_mode`选项，开启后不再支持旧版客户端
  - NPC添加`proto_version`选项，如需连接旧版服务器需要配置`-proto_version=0`
  - 重写客户端连接协议，防止探测、重放攻击等 （系统时间需要配置正确，依赖系统时间）
  - 更换哈希算法
  - 增加记录客户端本地IP地址
  - 修复最快IP解析
  - HTTP正向代理使用相对路径 [#75](https://github.com/mycoool/nps/issues/75)
  - 新增WS、WSS方式连接服务端 [#71](https://github.com/mycoool/nps/issues/71)
  - 客户端服务器双向认证
  - 允许独立配置连接协议
  - 网页添加命令行提示

- **v0.26.56 (2025-05-07)**
  - 日志相对路径使用配置路径
  - 日志添加`log_color`选项
  - 调整关闭日志优先级
  - 减少登录错误弹窗等待时间

- **v0.26.55 (2025-05-05)**
  - 文档添加自动翻译
  - 重写日志输出模块
  - 修复日志轮换功能
  - 修复日志权限问题 [#70](https://github.com/mycoool/nps/issues/70)
  - 更新上游依赖

- **v0.26.54 (2025-05-02)**
  - 更新文档说明
  - 添加弹窗翻译
  - 优化浏览器语言检测
  - 优化操作逻辑减少操作步骤 [#69](https://github.com/mycoool/nps/issues/69)

- **v0.26.53 (2025-04-25)**
  - P2P同时转发TCP和UDP端口

- **v0.26.52 (2025-04-23)**
  - 优化服务器域名解析逻辑
  - 修复同时启用TCP和KCP时客户端不同步问题

- **v0.26.51 (2025-04-22)**
  - 优化P2P打洞算法
  - 使用迭代法解析服务器域名
  - 优选最快IP连接服务器
  - 允许同时监听KCP端口

- **v0.26.50 (2025-04-19)**
  - 优化P2P探测和连接速度
  - 隧道编辑页面支持保存为新配置 [#8](https://github.com/mycoool/nps/issues/8)
  - 调整页面显示，添加排序支持

- **v0.26.49 (2025-04-18)**
  - vkey添加点击复制
  - 重写透明代理逻辑 [#59](https://github.com/mycoool/nps/issues/59)
  - 修复linux、darwin、freebsd的透明代理

- **v0.26.48 (2025-04-17)**
  - 添加点击自动复制命令行 [#62](https://github.com/mycoool/nps/issues/62)
  - 密码认证配置内容忽略空行
  - 修复NPS的IPv6自动识别
  - 修复管理页面显示
  - 隧道列表支持端口号排序
  - 重写客户端TLS功能，支持使用type传入tls （已弃用tls_enable）
  - 重写服务端TLS功能，支持TLS端口复用 （已弃用tls_enable）
  - 客户端支持连接多个服务器 [#9](https://github.com/mycoool/nps/issues/9)
  - 更新证书随机生成

- **v0.26.47 (2025-04-14)** 
  - 优化P2P处理逻辑
  - 服务端支持配置`p2p_ip=0.0.0.0`来自动识别IP地址(IPv4/IPv6由`dns_server`配置决定)
  - 服务端支持配置`p2p_ip=::`来强制自动识别使用IPv6地址
  - 修复P2P的IPv6支持
  - NPC自动选择IPv4/IPv6进行P2P连接
  - **新增** 支持单条隧道独立配置密码认证

- **v0.26.46 (2025-04-14)** 
  - 调整日志输出等级
  - 优化写入性能
  - 修复端口复用时连接泄露和并发冲突
  - 清理代码更新相关依赖
  - 新增OpenWRT仓库 [mycoool/nps-openwrt](https://github.com/mycoool/nps-openwrt)
  - 修复拼写错误
  - 自动更新[Android](https://github.com/mycoool/npsclient)和[OpenWrt](https://github.com/mycoool/nps-openwrt)仓库
  - 自动识别服务器IP [#59](https://github.com/mycoool/nps/issues/59)
  - P2P支持IPv6（需要纯IPv6网络环境）

- **v0.26.45 (2025-04-09)** 
  - 搜索功能匹配不限制大小写
  - 修复HTTP代理认证头 [#55](https://github.com/mycoool/nps/issues/55)
  - 添加编译架构 [#53](https://github.com/mycoool/nps/issues/53)
  - 增加自定义DNS支持非标准系统
  - 新增安卓客户端 [#53](https://github.com/mycoool/nps/issues/53) [mycoool/npsclient](https://github.com/mycoool/npsclient)
  - 美化下拉框样式，使用标准JSON保存数据 [#51](https://github.com/mycoool/nps/pull/51) (感谢[yhl452493373](https://github.com/yhl452493373))

- **v0.26.44 (2025-03-26)** 
  - 修复客户端超过1000不显示问题
  - **增强** 隧道添加支持搜索客户端

- **v0.26.43 (2025-03-24)** 
  - 修复客户端隧道编辑按钮缺失
  - 隧道列表隐藏无用信息
  - **新增** 域名转发隧道支持暂停
  - **增强** 域名转发防止扫描探测

- **v0.26.42 (2025-03-23)** 
  - 修复管理页面表单Id标签重复
  - 修复隧道页面不显示
  - 整理nps.conf文件

- **v0.26.41 (2025-03-22)** 
  - Docker自动创建NPS默认配置 **（一定要记得改配置）**
  - 固定管理页面左侧菜单、顶部标题、底部footer [#49](https://github.com/mycoool/nps/pull/49)
  - 优化运行速度，减少资源占用
  - 修复单条隧道流量统计 [#30](https://github.com/mycoool/nps/issues/30)
  - 增强流量统计颗粒度 **（注意：客户端流量是隧道流量出入总和的两倍）**
  - 修复文件模式访问
  - 调整管理页面文件模式显示
  - **新增** 管理页面表单选项持久化储存
  - **新增** 表单添加显示全部选项
  - **新增** 单条隧道支持限制流量和时间
  - 调整隧道页面显示
  - 修复NPC客户端NAT检测  

- **v0.26.40 (2025-03-21)** 
  - 前端页面美化 [#47](https://github.com/mycoool/nps/pull/47)
  - 增加docker支持架构，添加shell支持
  - 向NPS的docker镜像添加tzdata软件包支持时区配置 [#45](https://github.com/mycoool/nps/issues/45)
  - 私密代理支持通过TLS连接 [#37](https://github.com/mycoool/nps/issues/37)
  - docker添加主线分支发布
  - 修复连接数统计问题 [#48](https://github.com/mycoool/nps/issues/48)

- **v0.26.39 (2025-03-16)** 
  - 切换包至本仓库
  - 更新说明文档至当前版本
  - 更新管理页面帮助
  - 优化 nps.conf 配置文件
  - 更新 SDK 组件

- **v0.26.38 (2025-03-14)** 
  - 域名转发支持HTTP/2
  - 当配置请求域名修时同时修改Origin头避免后端监测
  - 调整域名编辑页面逻辑
  - 更新相关依赖，修复CVE-2025-22870
  - 使用 [XTLS/go-win7](https://github.com/XTLS/go-win7) 编译旧版代码支持Win7
  - 整理仓库代码
  - 优化域名查找算法

更多历史更新记录请参阅项目 [Releases](https://github.com/mycoool/nps/releases)
