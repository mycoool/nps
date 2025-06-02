package connection

import (
	"net"
	"os"
	"strconv"

	"github.com/beego/beego"
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/lib/pmux"
)

var pMux *pmux.PortMux
var BridgeIp string
var BridgeTcpIp string
var BridgeKcpIp string
var BridgeTlsIp string
var BridgeWsIp string
var BridgeWssIp string
var BridgePort string
var BridgeTcpPort string
var BridgeKcpPort string
var BridgeTlsPort string
var BridgeWsPort string
var BridgeWssPort string
var BridgePath string
var HttpsPort string
var HttpPort string
var WebPort string

func InitConnectionService() {
	BridgeIp = beego.AppConfig.String("bridge_ip")
	BridgeTcpIp = beego.AppConfig.DefaultString("bridge_tcp_ip", BridgeIp)
	BridgeKcpIp = beego.AppConfig.DefaultString("bridge_kcp_ip", BridgeIp)
	BridgeTlsIp = beego.AppConfig.DefaultString("bridge_tls_ip", BridgeIp)
	BridgeWsIp = beego.AppConfig.DefaultString("bridge_ws_ip", BridgeIp)
	BridgeWssIp = beego.AppConfig.DefaultString("bridge_wss_ip", BridgeIp)
	BridgePort = beego.AppConfig.String("bridge_port")
	BridgeTcpPort = beego.AppConfig.DefaultString("bridge_tcp_port", BridgePort)
	BridgeKcpPort = beego.AppConfig.DefaultString("bridge_kcp_port", BridgePort)
	BridgeTlsPort = beego.AppConfig.DefaultString("bridge_tls_port", beego.AppConfig.String("tls_bridge_port"))
	BridgeWsPort = beego.AppConfig.String("bridge_ws_port")
	BridgeWssPort = beego.AppConfig.String("bridge_wss_port")
	BridgePath = beego.AppConfig.String("bridge_path")
	HttpsPort = beego.AppConfig.String("https_proxy_port")
	HttpPort = beego.AppConfig.String("http_proxy_port")
	WebPort = beego.AppConfig.String("web_port")

	if HttpPort == BridgePort || HttpsPort == BridgePort || WebPort == BridgePort || BridgeTlsPort == BridgePort {
		port, err := strconv.Atoi(BridgePort)
		if err != nil {
			logs.Error("%v", err)
			os.Exit(0)
		}
		pMux = pmux.NewPortMux(port, beego.AppConfig.String("web_host"), beego.AppConfig.String("bridge_host"))
	}
}

func GetBridgeTcpListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is tcp, the bridge port is %s", BridgeTcpPort)
	var p int
	var err error
	if p, err = strconv.Atoi(BridgeTcpPort); err != nil {
		return nil, err
	}
	if pMux != nil && BridgeTcpPort == BridgePort {
		return pMux.GetClientListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(BridgeTcpIp), p, ""})
}

func GetBridgeTlsListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is tls, the bridge port is %s", BridgeTlsPort)
	var p int
	var err error
	if p, err = strconv.Atoi(BridgeTlsPort); err != nil {
		return nil, err
	}
	if pMux != nil && BridgeTlsPort == BridgePort {
		return pMux.GetClientTlsListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(BridgeTlsIp), p, ""})
}

func GetBridgeWsListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is ws, the bridge port is %s, the bridge path is %s", BridgeWsPort, BridgePath)
	var p int
	var err error
	if p, err = strconv.Atoi(BridgeWsPort); err != nil {
		return nil, err
	}
	if pMux != nil && BridgeWsPort == BridgePort {
		return pMux.GetClientWsListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(BridgeWsIp), p, ""})
}

func GetBridgeWssListener() (net.Listener, error) {
	logs.Info("server start, the bridge type is wss, the bridge port is %s, the bridge path is %s", BridgeWssPort, BridgePath)
	var p int
	var err error
	if p, err = strconv.Atoi(BridgeWssPort); err != nil {
		return nil, err
	}
	if pMux != nil && BridgeWssPort == BridgePort {
		return pMux.GetClientWssListener(), nil
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(BridgeWssIp), p, ""})
}

func GetHttpListener() (net.Listener, error) {
	if pMux != nil && HttpPort == BridgePort {
		logs.Info("start http listener, port is %s", BridgePort)
		return pMux.GetHttpListener(), nil
	}
	logs.Info("start http listener, port is %s", HttpPort)
	return getTcpListener(beego.AppConfig.String("http_proxy_ip"), HttpPort)
}

func GetHttpsListener() (net.Listener, error) {
	if pMux != nil && HttpsPort == BridgePort {
		logs.Info("start https listener, port is %s", BridgePort)
		return pMux.GetHttpsListener(), nil
	}
	logs.Info("start https listener, port is %s", HttpsPort)
	return getTcpListener(beego.AppConfig.String("http_proxy_ip"), HttpsPort)
}

func GetWebManagerListener() (net.Listener, error) {
	if pMux != nil && WebPort == BridgePort {
		logs.Info("Web management start, access port is %s", BridgePort)
		return pMux.GetManagerListener(), nil
	}
	logs.Info("web management start, access port is %s", WebPort)
	return getTcpListener(beego.AppConfig.String("web_ip"), WebPort)
}

func getTcpListener(ip, p string) (net.Listener, error) {
	port, err := strconv.Atoi(p)
	if err != nil {
		logs.Error("%v", err)
		os.Exit(0)
	}
	if ip == "" {
		ip = "0.0.0.0"
	}
	return net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(ip), port, ""})
}
