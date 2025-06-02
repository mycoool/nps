# 增强功能

## 1. NAT 类型检测

使用 STUN 服务器检测 NAT 类型：
```bash
./npc nat -stun_addr=stun.stunprotocol.org:3478
```
如果 **P2P 双方都是 `Symmetric NAT`** ，则 **无法穿透**，其他 NAT 组合通常可以成功。

📌 **可选参数**

| 参数           | 说明            | 默认值                          |
|--------------|---------------|------------------------------|
| `-stun_addr` | 指定 STUN 服务器地址 | `stun.stunprotocol.org:3478` |

---

## 2. 状态检查

检查 NPC 客户端的运行状态：
```bash
./npc status -config=/path/to/npc.conf
```
📌 **可选参数**

| 参数        | 说明            |
|-----------|---------------|
| `-config` | 指定 NPC 配置文件路径 |

---

## 3. 重载配置文件

重新加载 NPC 客户端配置，而无需重启进程：
```bash
./npc restart -config=/path/to/npc.conf
```
📌 **可选参数**

| 参数        | 说明            |
|-----------|---------------|
| `-config` | 指定 NPC 配置文件路径 |

---

## 4. 通过代理连接 NPS

如果 NPC 运行的机器无法直接访问外网，可以通过 **Socks5 / HTTP 代理** 连接 NPS 服务器。

### **4.1 配置文件方式**
在 `npc.conf` 文件中添加：
```ini
[common]
proxy_url=socks5://111:222@127.0.0.1:8024
```

### **4.2 命令行方式**
```bash
./npc -server=xxx:123 -vkey=xxx -proxy=socks5://111:222@127.0.0.1:8024
```

📌 **支持代理协议**

| 代理类型       | 示例格式                                 |
|------------|--------------------------------------|
| **Socks5** | `socks5://username:password@ip:port` |
| **HTTP**   | `http://username:password@ip:port`   |

---

## 5. 其他命令行参数
📌 **所有参数可与启动命令组合使用** ：

```bash
./npc -server=xxx:123,yyy:456 -vkey=xxx,yyy -type=tls,tcp -log=off -debug=false
```

| 参数                    | 说明                                                | 默认值                          |
|-----------------------|---------------------------------------------------|------------------------------|
| `-server`             | 指定 NPS 服务器地址（`ip:port`）                           | 无                            |
| `-vkey`               | 客户端认证密钥                                           | 无                            |
| `-config`             | 指定配置文件路径                                          | 无                            |
| `-proxy`              | 通过代理连接 NPS（支持 Socks5 / HTTP）                      | 无                            |
| `-debug`              | 是否启用调试模式                                          | `true`                       |
| `-log`                | 日志输出模式（`stdout` / `file` / `both` / `off`）        | `file`                       |
| `-log_path`           | NPC 日志路径（为空使用默认路径，`off` 禁用日志）                     | `npc.log`                    |
| `-log_level`          | 日志级别（trace、debug、info、warn、error、fatal、panic、off） | `trace`                      |
| `-log_compress`       | 是否启用日志压缩                                          | `false`                      |
| `-log_max_days`       | 日志最大保留天数（0 关闭）                                    | `7`                          |
| `-log_max_files`      | 最大日志文件数（0 关闭）                                     | `10`                         |
| `-log_max_size`       | 单个日志文件最大大小（MB）                                    | `5`                          |
| `-disconnect_timeout` | 连接超时秒数                                            | `60`                         |
| `-pprof`              | 启用 PProf 调试（格式 `ip:port`）                         | 无                            |
| `-local_type`         | P2P 目标类型                                          | `p2p`                        |
| `-local_port`         | P2P 本地端口                                          | `2000`                       |
| `-password`           | P2P 认证密码                                          | 无                            |
| `-stun_addr`          | STUN 服务器地址                                        | `stun.stunprotocol.org:3478` |
| `-dns_server`         | 配置 DNS 服务器                                        | `8.8.8.8`                    |
| `-time`               | 客户端注册时间（小时）                                       | `2`                          |
| `-type`               | 服务器连接方式（`tcp` / `tls` / `kcp`）                    | `tcp`                        |
| `-version`            | 显示当前版本                                            | 无                            |

---

## 6. 群晖支持

📌 **推荐使用 Docker 部署**
```bash
docker pull duan2001/npc
docker run -d --restart=always --name npc --net=host duan2001/npc -server=xxx:123,yyy:456 -vkey=xxx,yyy -type=tls,tcp -log=off
```
~~曾提供 `.spk` 群晖套件，但已不再维护，建议使用 Docker 方式运行。~~ 
✅[Telegram](https://t.me/npsdev) 内有第三方提供的群晖套件。

---

✅ **如需更多帮助，请查看 [文档](https://github.com/mycoool/nps) 或提交 [GitHub Issues](https://github.com/mycoool/nps/issues) 反馈问题。**