// Package common 提供各种通用工具函数
// 包括网络、加密、时间、文件、字符串处理等工具
package common

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"html/template"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/araddon/dateparse"
	"github.com/beevik/ntp"
	"github.com/mycoool/nps/lib/logs"
)

// ExtractHost 从输入字符串中提取主机地址（包含端口）
// 支持URL格式和纯地址格式
// 示例:
//
//	"https://example.com/path" -> "example.com"
//	"192.168.1.1:8080" -> "192.168.1.1:8080"
//	"[2001:db8::1]:80" -> "[2001:db8::1]:80"
//
// 返回:
//
//	string: 包含端口的主机地址
func ExtractHost(input string) string {
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Host != "" {
			return u.Host
		}
	}
	if idx := strings.IndexByte(input, '/'); idx != -1 {
		input = input[:idx]
	}
	return input
}

// RemovePortFromHost 从主机地址中移除端口号
// 正确处理IPv6地址的方括号
// 示例:
//
//	"192.168.1.1:8080" -> "192.168.1.1"
//	"[2001:db8::1]:80" -> "[2001:db8::1]"
//
// 返回:
//
//	string: 不包含端口的主机地址
func RemovePortFromHost(host string) string {
	if len(host) == 0 {
		return host
	}
	var idx int
	// IPv6
	if host[0] == '[' {
		if idx = strings.IndexByte(host, ']'); idx != -1 {
			return host[:idx+1]
		}
		return ""
	}
	// IPv4 or Domain
	if idx = strings.LastIndexByte(host, ':'); idx != -1 && idx == strings.IndexByte(host, ':') {
		return host[:idx]
	}
	return host
}

// GetIpByAddr 从地址中提取纯IP地址
// 移除IPv6的方括号和端口号
// 示例:
//
//	"192.168.1.1:8080" -> "192.168.1.1"
//	"[2001:db8::1]:80" -> "2001:db8::1"
//
// 返回:
//
//	string: 纯IP地址
func GetIpByAddr(host string) string {
	if len(host) == 0 {
		return host
	}
	var idx int
	// IPv6
	if host[0] == '[' {
		if idx = strings.IndexByte(host, ']'); idx != -1 {
			return host[1:idx]
		}
		return ""
	}
	// IPv4 or Domain
	if idx = strings.LastIndexByte(host, ':'); idx != -1 && idx == strings.IndexByte(host, ':') {
		return host[:idx]
	}
	return host
}

// IsDomain 判断字符串是否为域名
// 如果能解析为IP地址则返回false
//
// 参数:
//
//	s: 待判断的字符串
//
// 返回:
//
//	bool: true表示是域名
func IsDomain(s string) bool {
	return net.ParseIP(s) == nil
}

// GetPortByAddr 从地址中提取端口号
// 正确处理IPv6地址的方括号
// 示例:
//
//	"192.168.1.1:8080" -> 8080
//	"[2001:db8::1]:443" -> 443
//
// 返回:
//
//	int: 端口号，无效返回0
func GetPortByAddr(addr string) int {
	if len(addr) == 0 {
		return 0
	}
	// IPv6
	if addr[0] == '[' {
		if end := strings.IndexByte(addr, ']'); end != -1 && end+1 < len(addr) && addr[end+1] == ':' {
			portStr := addr[end+2:]
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
				return port
			}
		}
		return 0
	}
	// Other
	if idx := strings.LastIndexByte(addr, ':'); idx != -1 {
		portStr := addr[idx+1:]
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
			return port
		}
	}
	return 0
}

// GetPortStrByAddr 从地址中提取端口号（字符串格式）
//
// 返回:
//
//	string: 端口号字符串，无效返回空字符串
func GetPortStrByAddr(addr string) string {
	port := GetPortByAddr(addr)
	if port == 0 {
		return ""
	}
	return strconv.Itoa(port)
}

// ValidateAddr 验证地址格式是否正确
// 检查IP和端口是否有效
//
// 参数:
//
//	s: 待验证的地址
//
// 返回:
//
//	string: 验证通过返回原地址，否则返回空字符串
func ValidateAddr(s string) string {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); ip == nil {
		return ""
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return ""
	}
	return s
}

// BuildAddress 构建完整的地址字符串
// 正确处理IPv6地址的方括号
// 示例:
//
//	"192.168.1.1", "8080" -> "192.168.1.1:8080"
//	"2001:db8::1", "80" -> "[2001:db8::1]:80"
//
// 参数:
//
//	host: 主机或IP
//	port: 端口号
//
// 返回:
//
//	string: 完整的地址
func BuildAddress(host string, port string) string {
	if strings.Contains(host, ":") { // IPv6
		return fmt.Sprintf("[%s]:%s", host, port)
	}
	return fmt.Sprintf("%s:%s", host, port)
}

// SplitServerAndPath 分割服务器地址和路径
// 示例:
//
//	"example.com/path" -> "example.com", "/path"
//	"example.com" -> "example.com", ""
//
// 参数:
//
//	s: 完整地址
//
// 返回:
//
//	string: 服务器地址
//	string: 路径
func SplitServerAndPath(s string) (server, path string) {
	index := strings.Index(s, "/")
	if index == -1 {
		return s, ""
	}
	return s[:index], s[index:]
}

// SplitAddrAndHost 分割地址、主机名和SNI
// 支持格式：addr@host，如果host为空则使用addr
// 示例:
//
//	"1.2.3.4:443@example.com" -> "1.2.3.4:443", "example.com", "example.com"
//	"example.com:443" -> "example.com:443", "example.com", "example.com"
//
// 参数:
//
//	s: 完整地址
//
// 返回:
//
//	string: 连接地址
//	string: 主机名
//	string: SNI（如果host是IP则返回空）
func SplitAddrAndHost(s string) (addr, host, sni string) {
	s = strings.TrimSpace(s)
	index := strings.Index(s, "@")
	if index == -1 {
		return s, s, GetSni(s)
	}
	addr = strings.TrimSpace(s[:index])
	host = strings.TrimSpace(s[index+1:])
	if host == "" {
		return addr, addr, ""
	}
	return addr, host, GetSni(host)
}

// GetSni 从主机名中获取SNI（Server Name Indication）
// SNI只在域名时使用，IP地址时不使用
//
// 参数:
//
//	host: 主机名或IP
//
// 返回:
//
//	string: SNI，IP地址返回空字符串
func GetSni(host string) string {
	sni := GetIpByAddr(host)
	if !IsDomain(sni) {
		sni = ""
	}
	return sni
}

// GetHostByName 通过域名获取对应的 IP 地址（优先返回 IPv4，其次 IPv6）。
// 如果入参不是合法域名则原样返回。
func GetHostByName(hostname string) string {
	if !DomainCheck(hostname) {
		return hostname
	}
	ips, _ := net.LookupIP(hostname)
	for _, v := range ips {
		if v.To4() != nil {
			return v.String()
		}
		// If IPv4 not found, return IPv6
		if v.To16() != nil {
			return v.String()
		}
	}
	return ""
}

// DomainCheck 检查字符串是否为合法域名（可带 http/https 前缀，可带路径）。
func DomainCheck(domain string) bool {
	var match bool
	IsLine := "^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}(/)"
	NotLine := "^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}"
	match, _ = regexp.MatchString(IsLine, domain)
	if !match {
		match, _ = regexp.MatchString(NotLine, domain)
	}
	return match
}

// Max 返回一组整数中的最大值；values 为空时返回 math.MinInt。
func Max(values ...int) int {
	maxVal := math.MinInt
	for _, v := range values {
		if v > maxVal {
			maxVal = v
		}
	}
	return maxVal
}

// Min 返回一组整数中的最小值；values 为空时返回 math.MaxInt。
func Min(values ...int) int {
	minVal := math.MaxInt
	for _, v := range values {
		if v < minVal {
			minVal = v
		}
	}
	return minVal
}

// GetPort 将任意整数归一化为 [0, 65535] 范围内的端口值。
func GetPort(value int) int {
	if value >= 0 {
		return value % 65536
	}
	return (65536 + value%65536) % 65536
}

// CheckAuthWithAccountMap 检查用户认证信息
// 支持单账号、多账号、authMap三种认证方式
//
// 参数:
//
//	u: 当前登录用户名
//	p: 当前登录密码
//	user: 全局用户名
//	passwd: 全局密码
//	accountMap: 多账号映射表（username->password）
//	authMap: auth映射表（username->password）
//
// 返回:
//
//	bool: true表示认证成功
func CheckAuthWithAccountMap(u, p, user, passwd string, accountMap, authMap map[string]string) bool {
	// Single account check
	noAccountMap := len(accountMap) == 0
	noAuthMap := len(authMap) == 0
	if noAccountMap && noAuthMap {
		return u == user && p == passwd
	}

	// Multi-account authentication check
	if len(u) == 0 {
		return false
	}

	if u == user && p == passwd {
		return true
	}

	if !noAccountMap {
		if P, ok := accountMap[u]; ok && p == P {
			return true
		}
	}

	if !noAuthMap {
		if P, ok := authMap[u]; ok && p == P {
			return true
		}
	}

	return false
}

// CheckAuth 校验 HTTP Basic 认证（Authorization/Proxy-Authorization）。
func CheckAuth(r *http.Request, user, passwd string, accountMap, authMap map[string]string) bool {
	// Bypass authentication only if user, passwd are empty and multiAccount is nil or empty
	if user == "" && passwd == "" && len(accountMap) == 0 && len(authMap) == 0 {
		return true
	}

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		s = strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
		if len(s) != 2 {
			return false
		}
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return false
	}

	return CheckAuthWithAccountMap(pair[0], pair[1], user, passwd, accountMap, authMap)
}

// DealMultiUser 解析多用户配置字符串
// 支持换行符分隔的配置格式：username=password
//
// 参数:
//
//	s: 多用户配置字符串
//
// 返回:
//
//	map[string]string: 用户名->密码的映射
func DealMultiUser(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	s = strings.ReplaceAll(s, "\r\n", "\n")
	multiUserMap := make(map[string]string)
	for _, v := range strings.Split(s, "\n") {
		if strings.TrimSpace(v) == "" {
			continue
		}
		item := strings.SplitN(v, "=", 2)
		if len(item) == 0 {
			continue
		} else if len(item) == 1 {
			item = append(item, "")
		}
		multiUserMap[strings.TrimSpace(item[0])] = strings.TrimSpace(item[1])
	}
	return multiUserMap
}

// GetBoolByStr 将字符串转换为布尔值
//
// 参数:
//
//	s: 待转换的字符串
//
// 返回:
//
//	bool: "1"或"true"返回true，其他返回false
func GetBoolByStr(s string) bool {
	switch s {
	case "1", "true":
		return true
	}
	return false
}

// GetStrByBool 将布尔值转换为字符串
//
// 参数:
//
//	b: 布尔值
//
// 返回:
//
//	string: true返回"1"，false返回"0"
func GetStrByBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// GetIntNoErrByStr 将字符串转换为整数（忽略错误）
//
// 参数:
//
//	str: 待转换的字符串
//
// 返回:
//
//	int: 整数值，转换失败返回0
func GetIntNoErrByStr(str string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(str))
	return i
}

// GetTimeNoErrByStr 将字符串转换为时间对象（忽略错误）
// 支持Unix时间戳（秒或毫秒）和日期字符串
//
// 参数:
//
//	str: 待转换的字符串
//
// 返回:
//
//	time.Time: 时间对象，解析失败返回零时间
func GetTimeNoErrByStr(str string) time.Time {
	// 1. 去除前后空格
	str = strings.TrimSpace(str)
	if str == "" {
		return time.Time{} // 为空时返回零时间
	}

	// 2. 先尝试解析为 Unix 时间戳（秒或毫秒）
	if timestamp, err := strconv.ParseInt(str, 10, 64); err == nil {
		// 处理毫秒级时间戳
		if timestamp > 1_000_000_000_000 {
			return time.UnixMilli(timestamp)
		}
		// 处理秒级时间戳
		return time.Unix(timestamp, 0)
	}

	// 3. 使用 dateparse 库解析日期字符串
	t, err := dateparse.ParseLocal(str)
	if err == nil {
		return t
	}

	// 解析失败，返回零时间
	return time.Time{}
}

// ContainsFold 不区分大小写检查子串
//
// 参数:
//
//	s: 原字符串
//	substr: 待查找的子串
//
// 返回:
//
//	bool: true表示包含
func ContainsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// ReadAllFromFile 读取文件的全部内容
//
// 参数:
//
//	filePath: 文件路径
//
// 返回:
//
//	[]byte: 文件内容
//	error: 错误信息
func ReadAllFromFile(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// GetPath 获取文件的绝对路径
// 如果是相对路径则转换为绝对路径
//
// 参数:
//
//	filePath: 文件路径
//
// 返回:
//
//	string: 绝对路径
func GetPath(filePath string) string {
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(GetRunPath(), filePath)
	}
	path, err := filepath.Abs(filePath)
	if err != nil {
		return filePath
	}
	return path
}

// GetCertContent 读取证书文件内容
// 如果文件路径已经包含header标记则直接返回
//
// 参数:
//
//	filePath: 证书文件路径或内容
//	header: 证书标记（如"CERTIFICATE"）
//
// 返回:
//
//	string: 证书内容
//	error: 错误信息
func GetCertContent(filePath, header string) (string, error) {
	if filePath == "" || strings.Contains(filePath, header) {
		return filePath, nil
	}
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(GetRunPath(), filePath)
	}
	content, err := ReadAllFromFile(filePath)
	if err != nil || !strings.Contains(string(content), header) {
		return "", err
	}
	return string(content), nil
}

// LoadCertPair 并发加载证书和私钥文件
//
// 参数:
//
//	certFile: 证书文件路径
//	keyFile: 私钥文件路径
//
// 返回:
//
//	string: 证书内容
//	string: 私钥内容
//	bool: true表示加载成功
func LoadCertPair(certFile, keyFile string) (certContent, keyContent string, ok bool) {
	var wg sync.WaitGroup
	var certErr, keyErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		certContent, certErr = GetCertContent(certFile, "CERTIFICATE")
	}()
	go func() {
		defer wg.Done()
		keyContent, keyErr = GetCertContent(keyFile, "PRIVATE")
	}()
	wg.Wait()

	if certErr != nil || keyErr != nil || certContent == "" || keyContent == "" {
		return "", "", false
	}
	return certContent, keyContent, true
}

// LoadCert 加载TLS证书对
//
// 参数:
//
//	certFile: 证书文件路径
//	keyFile: 私钥文件路径
//
// 返回:
//
//	tls.Certificate: TLS证书对象
//	bool: true表示加载成功
func LoadCert(certFile, keyFile string) (tls.Certificate, bool) {
	certContent, keyContent, ok := LoadCertPair(certFile, keyFile)
	if ok {
		certificate, err := tls.X509KeyPair([]byte(certContent), []byte(keyContent))
		if err == nil {
			return certificate, true
		}
	}
	return tls.Certificate{}, false
}

// GetCertType 获取证书类型
//
// 参数:
//
//	s: 证书路径或内容
//
// 返回:
//
//	string: 类型："empty"、"text"、"file"、"invalid"
func GetCertType(s string) string {
	if s == "" {
		return "empty"
	}
	if strings.Contains(s, "-----BEGIN ") || strings.Contains(s, "\n") {
		return "text"
	}
	if _, err := os.Stat(s); err == nil {
		return "file"
	}
	return "invalid"
}

// FileExists 判断文件或目录是否存在。
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// TestTcpPort 检查指定 TCP 端口是否可监听。
func TestTcpPort(port int) bool {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: port})
	defer func() {
		if l != nil {
			_ = l.Close()
		}
	}()
	if err != nil {
		return false
	}
	return true
}

// TestUdpPort 检查指定 UDP 端口是否可监听。
func TestUdpPort(port int) bool {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: port})
	defer func() {
		if l != nil {
			_ = l.Close()
		}
	}()
	if err != nil {
		return false
	}
	return true
}

// BinaryWrite 写入长度和字节数据
// 使用长度前缀避免粘包问题
// 使用CONN_DATA_SEQ字符分隔数据
//
// 参数:
//
//	raw: 写入缓冲区
//	v: 待写入的字符串列表
func BinaryWrite(raw *bytes.Buffer, v ...string) {
	b := GetWriteStr(v...)
	_ = binary.Write(raw, binary.LittleEndian, int32(len(b)))
	_ = binary.Write(raw, binary.LittleEndian, b)
}

// GetWriteStr 获取带分隔符的序列化字符串
//
// 参数:
//
//	v: 待序列化的字符串列表
//
// 返回:
//
//	[]byte: 序列化后的字节数组
func GetWriteStr(v ...string) []byte {
	buffer := new(bytes.Buffer)
	var l int32
	for _, v := range v {
		l += int32(len([]byte(v))) + int32(len([]byte(CONN_DATA_SEQ)))
		_ = binary.Write(buffer, binary.LittleEndian, []byte(v))
		_ = binary.Write(buffer, binary.LittleEndian, []byte(CONN_DATA_SEQ))
	}
	return buffer.Bytes()
}

// InStrArr 检查字符串是否在数组中
//
// 参数:
//
//	arr: 字符串数组
//	val: 待查找的字符串
//
// 返回:
//
//	bool: true表示存在
func InStrArr(arr []string, val string) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}

// InIntArr 检查整数是否在数组中
//
// 参数:
//
//	arr: 整数数组
//	val: 待查找的整数
//
// 返回:
//
//	bool: true表示存在
func InIntArr(arr []int, val int) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}

// GetPorts 将端口字符串转换为整数数组
// 支持逗号分隔和范围格式（如：80,443,1000-2000）
//
// 参数:
//
//	s: 端口字符串
//
// 返回:
//
//	[]int: 排序后的端口数组
func GetPorts(s string) []int {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	seen := make(map[int]struct{})
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if fw := strings.SplitN(item, "-", 2); len(fw) == 2 {
			a, b := strings.TrimSpace(fw[0]), strings.TrimSpace(fw[1])
			if IsPort(a) && IsPort(b) {
				start, _ := strconv.Atoi(a)
				end, _ := strconv.Atoi(b)
				if end < start {
					start, end = end, start
				}
				for i := start; i <= end; i++ {
					seen[i] = struct{}{}
				}
			}
			continue
		}
		if IsPort(item) {
			port, _ := strconv.Atoi(item)
			seen[port] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	ps := make([]int, 0, len(seen))
	for p := range seen {
		ps = append(ps, p)
	}
	sort.Ints(ps)
	return ps
}

// IsPort 判断字符串是否为合法端口（1-65535）。
func IsPort(p string) bool {
	pi, err := strconv.Atoi(p)
	if err != nil {
		return false
	}
	if pi > 65535 || pi < 1 {
		return false
	}
	return true
}

// FormatAddress 规范化地址：如果仅提供端口，则补全为 127.0.0.1:port。
func FormatAddress(s string) string {
	if strings.Contains(s, ":") {
		return s
	}
	return "127.0.0.1:" + s
}

func in(target string, strArray []string) bool {
	sort.Strings(strArray)
	index := sort.SearchStrings(strArray, target)
	if index < len(strArray) && strArray[index] == target {
		return true
	}
	return false
}

// IsBlackIp 检查IP是否在黑名单中
//
// 参数:
//
//	ipPort: IP:Port格式的地址
//	vkey: 客户端vkey（用于日志）
//	blackIpList: 黑名单列表
//
// 返回:
//
//	bool: true表示在黑名单中
func IsBlackIp(ipPort, vkey string, blackIpList []string) bool {
	ip := GetIpByAddr(ipPort)
	if in(ip, blackIpList) {
		logs.Warn("IP [%s] is in the blacklist for [%s]", ip, vkey)
		return true
	}
	return false
}

// CopyBuffer 在两个读写器之间复制数据
// 使用CopyBuff池中的缓冲区提高性能
//
// 参数:
//
//	dst: 目标写入器
//	src: 源读取器
//	label: 可选的标签参数（用于调试）
//
// 返回:
//
//	int64: 写入的字节数
//	error: 错误信息
func CopyBuffer(dst io.Writer, src io.Reader, label ...string) (written int64, err error) {
	buf := CopyBuff.Get()
	defer CopyBuff.Put(buf)
	for {
		nr, er := src.Read(buf)
		//if len(pr)>0 && pr[0] && nr > 50 {
		//	logs.Warn(string(buf[:50]))
		//}
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}

// GetLocalUdpAddr 获取本地UDP地址
// 通过向自定义DNS服务器发送UDP包来获取本地IP
//
// 返回:
//
//	net.Conn: UDP连接（会立即关闭）
//	error: 错误信息
func GetLocalUdpAddr() (net.Conn, error) {
	tmpConn, err := net.Dial("udp", GetCustomDNS())
	if err != nil {
		return nil, err
	}
	return tmpConn, tmpConn.Close()
}

// GetLocalUdp4Addr 获取本地 IPv4 UDP 地址（通过外部 UDP 连接探测），连接会立即关闭。
func GetLocalUdp4Addr() (net.Conn, error) {
	tmpConn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	return tmpConn, tmpConn.Close()
}

// GetLocalUdp6Addr 获取本地 IPv6 UDP 地址（通过外部 UDP 连接探测），连接会立即关闭。
func GetLocalUdp6Addr() (net.Conn, error) {
	tmpConn, err := net.Dial("udp6", "[2400:3200::1]:53")
	if err != nil {
		return nil, err
	}
	return tmpConn, tmpConn.Close()
}

// ParseStr 解析模板字符串
// 使用Go模板语法，支持环境变量替换
//
// 参数:
//
//	str: 模板字符串（如：{{.USER}}）
//
// 返回:
//
//	string: 解析后的字符串
//	error: 错误信息
func ParseStr(str string) (string, error) {
	tmp := template.New("npc")
	var err error
	w := new(bytes.Buffer)
	if tmp, err = tmp.Parse(str); err != nil {
		return "", err
	}
	if err = tmp.Execute(w, GetEnvMap()); err != nil {
		return "", err
	}
	return w.String(), nil
}

// GetEnvMap 获取所有环境变量
//
// 返回:
//
//	map[string]string: 环境变量名->值的映射
func GetEnvMap() map[string]string {
	m := make(map[string]string)
	environ := os.Environ()
	for i := range environ {
		tmp := strings.Split(environ[i], "=")
		if len(tmp) == 2 {
			m[tmp[0]] = tmp[1]
		}
	}
	return m
}

// TrimArr 去掉字符串数组中的空元素（会 TrimSpace）。
func TrimArr(arr []string) []string {
	newArr := make([]string, 0)
	for _, v := range arr {
		trimmed := strings.TrimSpace(v) // 去除前后空白
		if trimmed != "" {
			newArr = append(newArr, trimmed)
		}
	}
	return newArr
}

// IsArrContains 检查数组是否包含指定值
//
// 参数:
//
//	arr: 字符串数组
//	val: 待查找的值
//
// 返回:
//
//	bool: true表示包含
func IsArrContains(arr []string, val string) bool {
	if arr == nil {
		return false
	}
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}

// RemoveArrVal 从字符串数组中移除指定值
//
// 参数:
//
//	arr: 字符串数组
//	val: 待移除的值
//
// 返回:
//
//	[]string: 移除后的数组
func RemoveArrVal(arr []string, val string) []string {
	for k, v := range arr {
		if v == val {
			arr = append(arr[:k], arr[k+1:]...)
			return arr
		}
	}
	return arr
}

// HandleArrEmptyVal 清理数组尾部空值，并将中间的空值继承为上一个非空值。
func HandleArrEmptyVal(list []string) []string {
	for len(list) > 0 && (list[len(list)-1] == "" || strings.TrimSpace(list[len(list)-1]) == "") {
		list = list[:len(list)-1]
	}

	for i := 0; i < len(list); i++ {
		list[i] = strings.TrimSpace(list[i])
		if i > 0 && list[i] == "" {
			list[i] = list[i-1]
		}
	}

	return list
}

// ExtendArrs 将多个字符串数组扩展到相同长度，缺失项使用最后一个值填充（空数组填充空字符串）。
func ExtendArrs(arrays ...*[]string) int {
	maxLength := 0
	for _, arr := range arrays {
		if len(*arr) > maxLength {
			maxLength = len(*arr)
		}
	}

	if maxLength == 0 {
		return 0
	}

	for _, arr := range arrays {
		for len(*arr) < maxLength {
			if len(*arr) == 0 {
				*arr = append(*arr, "")
			} else {
				*arr = append(*arr, (*arr)[len(*arr)-1])
			}
		}
	}

	return maxLength
}

// BytesToNum 将字节数组转换为数字
// 每个字节转换为对应的数字后拼接
// 示例：[1,2,3] -> 123
//
// 参数:
//
//	b: 字节数组
//
// 返回:
//
//	int: 转换后的数字
func BytesToNum(b []byte) int {
	var str string
	for i := 0; i < len(b); i++ {
		str += strconv.Itoa(int(b[i]))
	}
	x, _ := strconv.Atoi(str)
	return x
}

// GetSyncMapLen 获取 sync.Map 的元素数量（通过 Range 统计）。
func GetSyncMapLen(m *sync.Map) int {
	var c int
	m.Range(func(key, value interface{}) bool {
		c++
		return true
	})
	return c
}

// GetExtFromPath 从路径中提取第一个 '.' 前的有效段（历史兼容：这不是标准“扩展名”提取）。
func GetExtFromPath(path string) string {
	s := strings.Split(path, ".")
	re, err := regexp.Compile(`(\w+)`)
	if err != nil {
		return ""
	}
	return string(re.Find([]byte(s[0])))
}

// NormalizeIP 将 IP 规范化为 4 字节 IPv4 或 16 字节 IPv6 表示。
func NormalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// IsZeroIP 判断是否为零值 IP（0.0.0.0 / ::）。
func IsZeroIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.Equal(net.IPv4zero) || ip.Equal(net.IPv6zero)
}

// BuildUdpBindAddr 根据 serverIP/clientIP 推导 UDP 绑定网络类型与地址。
func BuildUdpBindAddr(serverIP string, clientIP net.IP) (network string, addr *net.UDPAddr) {
	if ip := net.ParseIP(serverIP); ip != nil && !IsZeroIP(ip) {
		if ip.To4() != nil {
			return "udp4", &net.UDPAddr{IP: ip, Port: 0}
		}
		return "udp6", &net.UDPAddr{IP: ip, Port: 0}
	}
	if clientIP != nil {
		if clientIP.To4() != nil {
			return "udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		}
		return "udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}
	}
	return "udp", &net.UDPAddr{IP: nil, Port: 0}
}

// IsSameIPType 判断两个地址字符串是否同为 IPv6（通过是否包含 '[' 粗略判断）。
func IsSameIPType(addr1, addr2 string) bool {
	ip1 := strings.Contains(addr1, "[")
	ip2 := strings.Contains(addr2, "[")

	if ip1 == ip2 {
		return true
	}
	return false
}

// GetMatchingLocalAddr 根据 remoteAddr 的 IP 类型（v4/v6）生成匹配的 localAddr。
func GetMatchingLocalAddr(remoteAddr, localAddr string) (string, error) {
	remoteIsV6 := strings.Contains(remoteAddr, "]:")
	localIsV6 := strings.Contains(localAddr, "]:")
	if remoteIsV6 == localIsV6 {
		return localAddr, nil
	}
	port := GetPortStrByAddr(localAddr)
	if remoteIsV6 {
		tmpConn, err := GetLocalUdp6Addr()
		if err != nil {
			return localAddr, fmt.Errorf("get local ipv6 addr: %w", err)
		}
		ip6 := tmpConn.LocalAddr().(*net.UDPAddr).IP.String()
		return fmt.Sprintf("[%s]:%s", ip6, port), nil
	} else {
		tmpConn, err := GetLocalUdp4Addr()
		if err != nil {
			return localAddr, fmt.Errorf("get local ipv4 addr: %w", err)
		}
		ip4 := tmpConn.LocalAddr().(*net.UDPAddr).IP.String()
		return fmt.Sprintf("%s:%s", ip4, port), nil
	}
}

var externalIp string
var ipApis = []string{
	"https://4.ipw.cn",
	"https://api.ipify.org",
	"http://ipinfo.io/ip",
	"https://api64.ipify.org",
	"https://6.ipw.cn",
	"http://api.ip.sb",
	"http://myexternalip.com/raw",
	"http://ifconfig.me/ip",
	"http://ident.me",
	"https://d-jy.net/ip",
}

// FetchExternalIp 通过多个公网 API 获取外网 IP，并缓存到包变量中。
func FetchExternalIp() string {
	for _, api := range ipApis {
		resp, err := http.Get(api)
		if err != nil {
			continue
		}
		content, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		ip := string(content)
		if IsValidIP(ip) {
			externalIp = ip
			return ip
		}
	}

	return ""
}

// GetExternalIp 获取缓存的外网 IP，若不存在则实时探测。
func GetExternalIp() string {
	if externalIp != "" {
		return externalIp
	}
	return FetchExternalIp()
}

// PickEgressIPFor 选择连接到 dstIP 时的本机出站 IP（通过 UDP Dial 探测）。
func PickEgressIPFor(dstIP net.IP) net.IP {
	if dstIP == nil {
		return nil
	}
	network := "udp4"
	if dstIP.To4() == nil {
		network = "udp6"
	}
	raddr := (&net.UDPAddr{IP: dstIP, Port: 9}).String()
	d := net.Dialer{Timeout: 300 * time.Millisecond}
	conn, err := d.Dial(network, raddr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la != nil && !IsZeroIP(la.IP) {
		return la.IP
	}
	return nil
}

// GetIntranetIp 获取本机内网 IP（非回环地址），失败返回 127.0.0.1。
func GetIntranetIp() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, address := range addrs {
		// 检查 IP 地址判断是否为回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

// GetOutboundIP 获取默认出站 IP（通过 UDP 连接探测），失败返回 127.0.0.1。
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", GetCustomDNS())
	if err != nil {
		return net.ParseIP("127.0.0.1")
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// GetOutboundIPv6 获取默认出站 IPv6（通过 UDP 连接探测），失败返回 nil。
func GetOutboundIPv6() net.IP {
	tmpConn, err := GetLocalUdp6Addr()
	if err == nil {
		return tmpConn.LocalAddr().(*net.UDPAddr).IP
	}
	return nil
}

// IsValidIP 判断字符串是否为合法 IP（IPv4/IPv6）。
func IsValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

// IsPublicIP 判断 IP 是否为公网地址（排除 loopback、link-local、RFC1918、IPv6 私有地址）。
func IsPublicIP(IP net.IP) bool {
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	// Check for IPv6 private addresses
	if ip6 := IP.To16(); ip6 != nil {
		if ip6.IsPrivate() {
			return false
		}
		return true
	}
	return false
}

// GetServerIp 获取服务端对外可用 IP：优先使用配置的 ip（非 0.0.0.0/::），否则根据本机出站地址推导。
func GetServerIp(ip string) string {
	if ip != "" && ip != "0.0.0.0" && ip != "::" {
		return ip
	}

	if ip == "::" {
		tmpConn, err := GetLocalUdp6Addr()
		if err == nil {
			return tmpConn.LocalAddr().(*net.UDPAddr).IP.String()
		}
	}

	return GetOutboundIP().String()
}

// GetServerIpByClientIp 根据客户端 IP 类型选择返回外网 IP 或内网 IP。
func GetServerIpByClientIp(clientIp net.IP) string {
	if IsPublicIP(clientIp) {
		return GetExternalIp()
	}
	return GetIntranetIp()
}

// EncodeIP encodes a net.IP to [1-byte ATYP] + [16-byte Address]
func EncodeIP(ip net.IP) []byte {
	buf := make([]byte, 17)
	if ip4 := ip.To4(); ip4 != nil {
		buf[0] = 0x01
		copy(buf[1:], ip4)
	} else {
		buf[0] = 0x04
		copy(buf[1:], ip.To16())
	}
	return buf
}

// DecodeIP 解码IP地址
// 解码格式：[1-byte ATYP] + [16-byte Address]
//
// 参数:
//
//	data: 17字节的编码数据
//
// 返回:
//
//	net.IP: IP地址对象
func DecodeIP(data []byte) net.IP {
	if len(data) < 17 {
		return nil
	}
	atyp := data[0]
	addr := data[1:17]
	switch atyp {
	case 0x01:
		return net.IPv4(addr[0], addr[1], addr[2], addr[3])
	case 0x04:
		return addr
	default:
		return nil
	}
}

// JoinHostPort 等价于 net.JoinHostPort。
func JoinHostPort(host string, port string) string {
	return net.JoinHostPort(host, port)
}

// RandomBytes 生成随机字节数组
// 长度随机范围为[0, maxLen]
//
// 参数:
//
//	maxLen: 最大长度
//
// 返回:
//
//	[]byte: 随机字节数组
//	error: 错误信息
func RandomBytes(maxLen int) ([]byte, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(maxLen+1)))
	if err != nil {
		return nil, err
	}
	n := int(nBig.Int64())
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// SetTimezone 设置时区
//
// 参数:
//
//	tz: 时区字符串（如："Asia/Shanghai"）
//
// 返回:
//
//	error: 错误信息
func SetTimezone(tz string) error {
	if tz == "" {
		return nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return err
	}
	time.Local = loc
	return nil
}

var (
	timeOffset   time.Duration
	ntpServer    string
	syncInterval = 5 * time.Minute
	lastSyncMono time.Time
	timeMutex    sync.RWMutex
	syncCh       = make(chan struct{}, 1)
)

// SetNtpServer 设置 NTP 服务器地址（空字符串表示关闭 NTP 校准）。
func SetNtpServer(server string) {
	timeMutex.Lock()
	defer timeMutex.Unlock()
	ntpServer = server
}

// SetNtpInterval 设置 NTP 同步间隔。
func SetNtpInterval(d time.Duration) {
	timeMutex.Lock()
	defer timeMutex.Unlock()
	syncInterval = d
}

// CalibrateTimeOffset 与 NTP 服务器校准时间并返回偏移量。
func CalibrateTimeOffset(server string) (time.Duration, error) {
	if server == "" {
		return 0, nil
	}
	ntpTime, err := ntp.Time(server)
	if err != nil {
		return 0, err
	}
	return time.Until(ntpTime), nil
}

// TimeOffset 获取当前的时间偏移量
//
// 返回:
//
//	time.Duration: 时间偏移量
func TimeOffset() time.Duration {
	timeMutex.RLock()
	defer timeMutex.RUnlock()
	return timeOffset
}

// TimeNow 获取校准后的当前时间
// 返回本地时间加上NTP校准的偏移量
//
// 返回:
//
//	time.Time: 校准后的时间
func TimeNow() time.Time {
	SyncTime()
	timeMutex.RLock()
	defer timeMutex.RUnlock()
	return time.Now().Add(timeOffset)
}

// SyncTime 同步NTP时间
// 定期与NTP服务器同步时间，计算并存储偏移量
// 使用syncCh确保同一时间只有一个同步协程在运行
func SyncTime() {
	timeMutex.RLock()
	srv, last := ntpServer, lastSyncMono
	interval := syncInterval
	timeMutex.RUnlock()

	if srv == "" || (!last.IsZero() && time.Since(last) < interval) {
		return
	}

	select {
	case syncCh <- struct{}{}:
		defer func() { <-syncCh }()
	default:
		return
	}

	now := time.Now()
	timeMutex.Lock()
	lastSyncMono = now
	timeMutex.Unlock()

	offset, err := CalibrateTimeOffset(srv)
	if err != nil {
		logs.Error("ntp[%s] sync failed: %v", srv, err)
	}

	timeMutex.Lock()
	timeOffset = offset
	timeMutex.Unlock()

	if offset != 0 {
		logs.Info("ntp[%s] offset=%v", srv, offset)
	}
}

// TimestampToBytes 将时间戳转换为字节数组（大端序）
// 8字节
//
// 参数:
//
//	ts: Unix时间戳
//
// 返回:
//
//	[]byte: 8字节的字节数组
func TimestampToBytes(ts int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(ts))
	return b
}

// BytesToTimestamp 将字节数组转换为时间戳（大端序）
// 8字节
//
// 参数:
//
//	b: 8字节的字节数组
//
// 返回:
//
//	int64: Unix时间戳
func BytesToTimestamp(b []byte) int64 {
	return int64(binary.BigEndian.Uint64(b))
}

// ValidatePoW 验证工作量证明（Proof of Work）
// 检查SHA256哈希的前bits位是否全为0
//
// 参数:
//
//	bits: 需要的零比特位数量（1-256）
//	parts: 待验证的字符串片段
//
// 返回:
//
//	bool: true表示验证通过
func ValidatePoW(bits int, parts ...string) bool {
	if bits < 1 || bits > 256 {
		return false
	}

	data := strings.Join(parts, "")
	sum := sha256.Sum256([]byte(data))
	fullBytes := bits / 8
	for i := 0; i < fullBytes; i++ {
		if sum[i] != 0 {
			return false
		}
	}
	remBits := bits % 8
	if remBits > 0 {
		mask := byte(0xFF << (8 - remBits))
		if (sum[fullBytes] & mask) != 0 {
			return false
		}
	}
	return true
}

// IsTrustedProxy 检查IP是否为受信任的代理
// 支持CIDR、通配符、精确匹配
//
// 参数:
//
//	list: 受信任的IP列表（逗号分隔）
//	      支持格式：
//	      - *: 全部信任
//	      - 192.168.1.0/24: CIDR
//	      - 192.168.*.*: 通配符
//	      - 1.2.3.4: 精确IP
//	ipStr: 待检查的IP地址
//
// 返回:
//
//	bool: true表示是受信任的代理
func IsTrustedProxy(list, ipStr string) bool {
	if list == "" || ipStr == "" {
		return false
	}

	ipStr = strings.TrimSpace(ipStr)

	if h, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = h
	}
	if strings.HasPrefix(ipStr, "[") && strings.HasSuffix(ipStr, "]") {
		ipStr = ipStr[1 : len(ipStr)-1]
	}
	if i := strings.LastIndex(ipStr, "%"); i != -1 { // fe80::1%eth0
		ipStr = ipStr[:i]
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()

	for _, raw := range strings.Split(list, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		if entry == "*" {
			return true
		}

		// CIDR（IPv4/IPv6）
		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}

		// if "192.168.*.*"
		if strings.Contains(entry, "*") {
			if ip4 == nil {
				continue
			}
			pSegs := strings.Split(entry, ".")
			if len(pSegs) != 4 {
				continue
			}
			matched := true
			for i := 0; i < 4; i++ {
				if pSegs[i] == "*" {
					continue
				}
				n, err := strconv.Atoi(pSegs[i])
				if err != nil || n < 0 || n > 255 || int(ip4[i]) != n {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
			continue
		}

		if e := net.ParseIP(entry); e != nil && e.Equal(ip) {
			return true
		}
	}

	return false
}
