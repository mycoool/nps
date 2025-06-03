# NPS Intranet Tunneling

[![GitHub stars](https://img.shields.io/github/stars/mycoool/nps.svg)](https://github.com/mycoool/nps)
[![GitHub forks](https://img.shields.io/github/forks/mycoool/nps.svg)](https://github.com/mycoool/nps)
[![Release](https://github.com/mycoool/nps/workflows/Release/badge.svg)](https://github.com/mycoool/nps/actions)
[![GitHub All Releases](https://img.shields.io/github/downloads/mycoool/nps/total)](https://github.com/mycoool/nps/releases)

- [中文文档](https://github.com/mycoool/nps/blob/master/README.md)

---

## Introduction

NPS is a lightweight and efficient intranet tunneling proxy server that supports forwarding multiple protocols (TCP, UDP, HTTP, HTTPS, SOCKS5, etc.). It features an intuitive web management interface that allows secure and convenient access to intranet resources from external networks, addressing a wide range of complex scenarios.

Due to the long-term discontinuation of [NPS](https://github.com/ehang-io/nps), this repository is a community-driven, updated fork based on nps 0.26.

- **Before asking questions, please check:** [Documentation](https://d-jy.net/docs/nps/) and [Issues](https://github.com/mycoool/nps/issues)
- **Contributions welcome:** Submit PRs, provide feedback or suggestions, and help drive the project forward.
- **Join the discussion:** Connect with other users in our [Telegram Group](https://t.me/npsdev).
- **Android:**  [mycoool/npsclient](https://github.com/mycoool/npsclient)
- **OpenWrt:**  [mycoool/nps-openwrt](https://github.com/mycoool/nps-openwrt)

---

## Key Features

- **Multi-Protocol Support**  
  Offers TCP/UDP forwarding, HTTP/HTTPS forwarding, HTTP/SOCKS5 proxy, P2P mode, and more to suit various intranet access scenarios.

- **Cross-Platform Deployment**  
  Compatible with major platforms like Linux and Windows, with easy installation as a system service.

- **Web Management Interface**  
  Provides real-time monitoring of traffic, connection statuses, and client performance in an intuitive interface.

- **Security and Extensibility**  
  Includes built-in encryption, traffic limiting, certificate management, and other features to ensure data security.

---

## Installation and Usage

For more detailed configuration options, please refer to the [Documentation](https://d-jy.net/docs/nps/) (some sections may be outdated).

### [Android](https://github.com/mycoool/npsclient) | [OpenWrt](https://github.com/mycoool/nps-openwrt)

### Docker Deployment

**DockerHub:**  [NPS](https://hub.docker.com/r/mycoool/nps) | [NPC](https://hub.docker.com/r/mycoool/npc)

**GHCR:**  [NPS](https://github.com/mycoool/nps/pkgs/container/nps) | [NPC](https://github.com/mycoool/nps/pkgs/container/npc)

#### NPS Server
```bash
docker pull mycoool/nps
docker run -d --restart=always --name nps --net=host -v $(pwd)/conf:/conf -v /etc/localtime:/etc/localtime:ro mycoool/nps
```

#### NPC Client
```bash
docker pull mycoool/npc
docker run -d --restart=always --name npc --net=host mycoool/npc -server=xxx:123,yyy:456 -vkey=key1,key2 -type=tls,tcp -log=off
```

### Server Installation

#### Linux
```bash
# Install (default configuration path: /etc/nps/; binary file path: /usr/bin/)
./nps install
nps start|stop|restart|uninstall

# Update
nps stop
nps-update update
nps start
```

#### Windows
> Windows 7 users should use the version ending with old: [64](https://github.com/mycoool/nps/releases/latest/download/windows_amd64_server_old.tar.gz) / [32](https://github.com/mycoool/nps/releases/latest/download/windows_386_server_old.tar.gz) (manual updates required)
```powershell
.\nps.exe install
.\nps.exe start|stop|restart|uninstall

# Update
.\nps.exe stop
.\nps-update.exe update
.\nps.exe start
```

### Client Installation

#### Linux
```bash
./npc install
/usr/bin/npc install -server=xxx:123,yyy:456 -vkey=xxx,yyy -type=tls -log=off
npc start|stop|restart|uninstall

# Update
npc stop
/usr/bin/npc-update update
npc start
```

#### Windows
> Windows 7 users should use the version ending with old: [64](https://github.com/mycoool/nps/releases/latest/download/windows_amd64_client_old.tar.gz) / [32](https://github.com/mycoool/nps/releases/latest/download/windows_386_client_old.tar.gz) (manual updates required)
```powershell
.\npc.exe install -server="xxx:123,yyy:456" -vkey="xxx,yyy" -type="tls,tcp" -log="off"
.\npc.exe start|stop|restart|uninstall

# Update
.\npc.exe stop
.\npc-update.exe update
.\npc.exe start
```

> **Tip:** The client supports connecting to multiple servers simultaneously. Example:  
> `npc -server=xxx:123,yyy:456,zzz:789 -vkey=key1,key2,key3 -type=tcp,tls`  
> Here, `xxx:123` uses TCP, and `yyy:456` and `zzz:789` use TLS.