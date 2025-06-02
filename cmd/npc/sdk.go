package main

import (
	"C"

	"github.com/mycoool/nps/client"
	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/logs"
	"github.com/mycoool/nps/lib/version"
)

var cl *client.TRPClient

func init() {
	logs.EnableInMemoryBuffer(0) // 0 = Default 64KB
	logs.Init("off", "trace", "", 0, 0, 0, false, false)
}

//export StartClientByVerifyKey
func StartClientByVerifyKey(serverAddr, verifyKey, connType, proxyUrl *C.char) int {
	if cl != nil {
		cl.Close()
	}
	cl = client.NewRPClient(C.GoString(serverAddr), C.GoString(verifyKey), C.GoString(connType), C.GoString(proxyUrl), nil, 60)
	cl.Start()
	return 1
}

//export GetClientStatus
func GetClientStatus() int {
	return client.NowStatus
}

//export CloseClient
func CloseClient() {
	if cl != nil {
		cl.Close()
	}
}

//export Version
func Version() *C.char {
	return C.CString(version.VERSION)
}

//export SetLogsLevel
func SetLogsLevel(logsLevel *C.char) {
	logs.SetLevel(C.GoString(logsLevel))
}

//export Logs
func Logs() *C.char {
	return C.CString(logs.GetBufferedLogs())
}

//export SetDnsServer
func SetDnsServer(dnsServer *C.char) {
	common.SetCustomDNS(C.GoString(dnsServer))
}

func main() {
	// Need a main function to make CGO compile package as C shared library
}
