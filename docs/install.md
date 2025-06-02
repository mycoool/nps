# 安装指南

NPS 提供多种安装方式，推荐使用 **Docker 部署**，也支持 **二进制发布包安装** 及 **源码编译**。

---

## 1. Docker 安装（推荐）

提供 Docker 镜像，支持 **DockerHub** 和 **GitHub Container Registry (GHCR)** 。

### **1.1 NPS 服务器端**

#### **DockerHub（推荐）**
```bash
docker pull duan2001/nps
docker run -d --restart=always --name nps --net=host -v <本机conf目录>:/conf -v /etc/localtime:/etc/localtime:ro duan2001/nps
```

#### **GHCR（可选）**
```bash
docker pull ghcr.io/mycoool/nps
docker run -d --restart=always --name nps --net=host -v <本机conf目录>:/conf -v /etc/localtime:/etc/localtime:ro ghcr.io/mycoool/nps
```

---

### **1.2 NPC 客户端**

#### **DockerHub（推荐）**
```bash
docker pull duan2001/npc
docker run -d --restart=always --name npc --net=host duan2001/npc -server=xxx:123,yyy:456 -vkey=xxx,yyy -type=tls,tcp -log=off
```

#### **GHCR（可选）**
```bash
docker pull ghcr.io/djylb/npc
docker run -d --restart=always --name npc --net=host ghcr.io/djylb/npc -server=xxx:123,yyy:456 -vkey=xxx,yyy -type=tls,tcp -log=off
```

---

## 2. 发布包安装

NPS 提供官方二进制安装包，适用于 **Windows、Linux、macOS、FreeBSD** 等多种平台。

📌 **下载地址**：[🔗 最新发布页面](https://github.com/mycoool/nps/releases/latest)

---

### **2.1 Windows 安装**

**Windows 10/11 用户（推荐）**：
- [64 位（Server）](https://github.com/mycoool/nps/releases/latest/download/windows_amd64_server.tar.gz)
- [64 位（Client）](https://github.com/mycoool/nps/releases/latest/download/windows_amd64_client.tar.gz)
- [32 位（Server）](https://github.com/mycoool/nps/releases/latest/download/windows_386_server.tar.gz)
- [32 位（Client）](https://github.com/mycoool/nps/releases/latest/download/windows_386_client.tar.gz)
- [ARM64（Server）](https://github.com/mycoool/nps/releases/latest/download/windows_arm64_server.tar.gz)
- [ARM64（Client）](https://github.com/mycoool/nps/releases/latest/download/windows_arm64_client.tar.gz)

**Windows 7 用户（使用 `old` 结尾版本）**：
- [64 位（Server）](https://github.com/mycoool/nps/releases/latest/download/windows_amd64_server_old.tar.gz)
- [64 位（Client）](https://github.com/mycoool/nps/releases/latest/download/windows_amd64_client_old.tar.gz)
- [32 位（Server）](https://github.com/mycoool/nps/releases/latest/download/windows_386_server_old.tar.gz)
- [32 位（Client）](https://github.com/mycoool/nps/releases/latest/download/windows_386_client_old.tar.gz)

📌 **安装方式（解压后进入文件夹）**
```powershell
# NPS 服务器
.\nps.exe install
.\nps.exe start|stop|restart|uninstall

# 支持指定配置文件路径
.\nps.exe -conf_path="D:\test\nps"
.\nps.exe install -conf_path="D:\test\nps"

# 更新
.\nps.exe stop
.\nps-update.exe update
.\nps.exe start

# NPC 客户端
.\npc.exe install -server="xxx:123,yyy:456" -vkey="xxx,yyy" -type="tcp,tls" -log="off"
.\npc.exe start|stop|restart|uninstall

# 更新
.\npc.exe stop
.\npc-update.exe update
.\npc.exe start
```

> **Windows 7 旧版** 不支持命令更新，如需升级请手动替换文件。

---

### **2.2 Linux 安装**
📌 **推荐使用 Docker 运行。**

#### **X86/64**
- [64 位（Server）](https://github.com/mycoool/nps/releases/latest/download/linux_amd64_server.tar.gz)
- [64 位（Client）](https://github.com/mycoool/nps/releases/latest/download/linux_amd64_client.tar.gz)
- [32 位（Server）](https://github.com/mycoool/nps/releases/latest/download/linux_386_server.tar.gz)
- [32 位（Client）](https://github.com/mycoool/nps/releases/latest/download/linux_386_client.tar.gz)

#### **ARM**
- [ARM64（Server）](https://github.com/mycoool/nps/releases/latest/download/linux_arm64_server.tar.gz)
- [ARM64（Client）](https://github.com/mycoool/nps/releases/latest/download/linux_arm64_client.tar.gz)
- [ARMv5（Server）](https://github.com/mycoool/nps/releases/latest/download/linux_arm_v5_server.tar.gz)
- [ARMv5（Client）](https://github.com/mycoool/nps/releases/latest/download/linux_arm_v5_client.tar.gz)
- [ARMv6（Server）](https://github.com/mycoool/nps/releases/latest/download/linux_arm_v6_server.tar.gz)
- [ARMv6（Client）](https://github.com/mycoool/nps/releases/latest/download/linux_arm_v6_client.tar.gz)
- [ARMv7（Server）](https://github.com/mycoool/nps/releases/latest/download/linux_arm_v7_server.tar.gz)
- [ARMv7（Client）](https://github.com/mycoool/nps/releases/latest/download/linux_arm_v7_client.tar.gz)

📌 **安装方式（解压后进入文件夹）**
```bash
# NPS 服务器
./nps install
nps start|stop|restart|uninstall

# 支持指定配置文件路径
./nps -conf_path="/app/nps"
./nps install -conf_path="/app/nps"

# 更新
nps stop
nps-update update
nps start
# 热更新
nps update && mv /usr/local/bin/nps /usr/bin/nps && nps restart

# NPC 客户端
./npc install
/usr/bin/npc install -server=xxx:123,yyy:456 -vkey=xxx,yyy -type=tcp,tls -log=off
npc start|stop|restart|uninstall

# 更新
npc stop
/usr/bin/npc-update update
npc start
# 热更新
npc update && mv /usr/local/bin/npc /usr/bin/npc && npc restart
```

---

### **2.3 macOS 安装**
- [Intel（Server）](https://github.com/mycoool/nps/releases/latest/download/darwin_amd64_server.tar.gz)
- [Intel（Client）](https://github.com/mycoool/nps/releases/latest/download/darwin_amd64_client.tar.gz)
- [Apple Silicon（Server）](https://github.com/mycoool/nps/releases/latest/download/darwin_arm64_server.tar.gz)
- [Apple Silicon（Client）](https://github.com/mycoool/nps/releases/latest/download/darwin_arm64_client.tar.gz)

📌 **安装方式（解压后进入文件夹）**
```bash
# NPS 服务器
./nps install
nps start|stop|restart|uninstall

# 支持指定配置文件路径
./nps -conf_path="/app/nps"
./nps install -conf_path="/app/nps"

# 更新
nps stop
nps-update update
nps start
# 热更新
nps update && mv /usr/local/bin/nps /usr/bin/nps && nps restart

# NPC 客户端
./npc install
/usr/bin/npc install -server=xxx:123,yyy:123 -vkey=xxx,yyy -type=tcp,tls -log=off
npc start|stop|restart|uninstall

# 更新
npc stop
/usr/bin/npc-update update
npc start
# 热更新
npc update && mv /usr/local/bin/npc /usr/bin/npc && npc restart
```

---

### **2.4 FreeBSD 安装**
- [AMD64（Server）](https://github.com/mycoool/nps/releases/latest/download/freebsd_amd64_server.tar.gz)
- [AMD64（Client）](https://github.com/mycoool/nps/releases/latest/download/freebsd_amd64_client.tar.gz)
- [386（Server）](https://github.com/mycoool/nps/releases/latest/download/freebsd_386_server.tar.gz)
- [386（Client）](https://github.com/mycoool/nps/releases/latest/download/freebsd_386_client.tar.gz)
- [ARM（Server）](https://github.com/mycoool/nps/releases/latest/download/freebsd_arm_server.tar.gz)
- [ARM（Client）](https://github.com/mycoool/nps/releases/latest/download/freebsd_arm_client.tar.gz)

---

## 3. Android 使用

### **3.1 APK (仅限NPC)**
#### [NPS Client](https://github.com/mycoool/npsclient)
#### [Google Play](https://play.google.com/store/apps/details?id=com.duanlab.npsclient)
- [全架构](https://github.com/mycoool/npsclient/releases/latest/download/app-universal-release.apk)
- [ARM64](https://github.com/mycoool/npsclient/releases/latest/download/app-arm64-v8a-release.apk)
- [ARM32](https://github.com/mycoool/npsclient/releases/latest/download/app-armeabi-v7a-release.apk)
- [X8664](https://github.com/mycoool/npsclient/releases/latest/download/app-x86_64-release.apk)


### **3.2 Termux 运行**
- [ARM64（Server）](https://github.com/mycoool/nps/releases/latest/download/android_arm64_server.tar.gz)
- [ARM64（Client）](https://github.com/mycoool/nps/releases/latest/download/android_arm64_client.tar.gz)。

---

## 4. OpenWrt 使用

#### [mycoool/nps-openwrt](https://github.com/mycoool/nps-openwrt)

---

## 5. 源码安装（Go 编译）

### **5.1 安装依赖**
```bash
go get -u github.com/mycoool/nps
```

### **5.2 编译**
#### **NPS 服务器**
```bash
go build -o nps cmd/nps/nps.go
```

#### **NPC 客户端**
```bash
go build -o npc cmd/npc/npc.go
```

编译完成后，即可使用 `./nps` 或 `./npc` 启动。

---

## 6. 相关链接

- **最新发布版本**：[GitHub Releases](https://github.com/mycoool/nps/releases/latest)
- **Android**：[mycoool/npsclient](https://github.com/mycoool/npsclient)
- **OpenWrt**：[mycoool/nps-openwrt](https://github.com/mycoool/nps-openwrt)
- **DockerHub 镜像**
  - [NPS Server](https://hub.docker.com/r/duan2001/nps)
  - [NPC Client](https://hub.docker.com/r/duan2001/npc)
- **GHCR 镜像**
  - [NPS Server](https://github.com/mycoool/nps/pkgs/container/nps)
  - [NPC Client](https://github.com/mycoool/nps/pkgs/container/npc)
