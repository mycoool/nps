// Package pmux This module is used for port reuse
// Distinguish client, web manager , HTTP and HTTPS according to the difference of protocol
package pmux

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/crypt"
	"github.com/mycoool/nps/lib/logs"
	"github.com/pkg/errors"
)

const (
	HTTP_GET        = 716984
	HTTP_POST       = 807983
	HTTP_HEAD       = 726965
	HTTP_PUT        = 808585
	HTTP_DELETE     = 686976
	HTTP_CONNECT    = 677978
	HTTP_OPTIONS    = 798084
	HTTP_TRACE      = 848265
	CLIENT          = 848384
	ACCEPT_TIME_OUT = 10
)

type PortMux struct {
	net.Listener
	port          int
	isClose       bool
	managerHost   string
	clientHost    string
	clientConn    chan *PortConn
	clientTlsConn chan *PortConn
	clientWsConn  chan *PortConn
	clientWssConn chan *PortConn
	httpConn      chan *PortConn
	httpsConn     chan *PortConn
	managerConn   chan *PortConn
}

func NewPortMux(port int, managerHost, clientHost string) *PortMux {
	pMux := &PortMux{
		managerHost:   managerHost,
		clientHost:    clientHost,
		port:          port,
		clientConn:    nil,
		clientTlsConn: nil,
		httpConn:      nil,
		httpsConn:     nil,
		managerConn:   nil,
	}
	pMux.Start()
	return pMux
}

func (pMux *PortMux) Start() error {
	// Port multiplexing is based on TCP only
	tcpAddr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:"+strconv.Itoa(pMux.port))
	if err != nil {
		return err
	}
	pMux.Listener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		logs.Error("%v", err)
		os.Exit(0)
	}
	go func() {
		for {
			conn, err := pMux.Listener.Accept()
			if err != nil {
				logs.Warn("%v", err)
				//close
				pMux.Close()
			}
			go pMux.process(conn)
		}
	}()
	return nil
}

func (pMux *PortMux) process(conn net.Conn) {
	// Recognition according to different signs
	// read 3 byte
	buf := make([]byte, 3)
	if n, err := io.ReadFull(conn, buf); err != nil || n != 3 {
		return
	}
	var ch chan *PortConn
	var rs []byte
	var buffer bytes.Buffer
	var readMore = false
	switch common.BytesToNum(buf) {
	case HTTP_CONNECT, HTTP_DELETE, HTTP_GET, HTTP_HEAD, HTTP_OPTIONS, HTTP_POST, HTTP_PUT, HTTP_TRACE: //http and manager
		i := 0
		if pMux.httpConn != nil {
			i++
		}
		if pMux.managerConn != nil {
			i++
		}
		if pMux.clientWsConn != nil {
			i++
		}
		if i > 1 {
			buffer.Reset()
			r := bufio.NewReader(conn)
			buffer.Write(buf)
			for {
				b, _, err := r.ReadLine()
				if err != nil {
					logs.Warn("read line error %v", err)
					conn.Close()
					break
				}
				buffer.Write(b)
				buffer.Write([]byte("\r\n"))
				if strings.Index(string(b), "Host:") == 0 || strings.Index(string(b), "host:") == 0 {
					// Remove host and space effects
					str := strings.Replace(string(b), "Host:", "", -1)
					str = strings.Replace(str, "host:", "", -1)
					str = strings.TrimSpace(str)
					// Determine whether it is the same as the manager domain name
					if common.GetIpByAddr(str) == pMux.managerHost && pMux.managerConn != nil {
						ch = pMux.managerConn
					} else if common.GetIpByAddr(str) == pMux.clientHost && pMux.clientWsConn != nil {
						ch = pMux.clientWsConn
					} else if pMux.httpConn != nil {
						ch = pMux.httpConn
					}
					b, _ := r.Peek(r.Buffered())
					buffer.Write(b)
					rs = buffer.Bytes()
					break
				}
			}
		} else if pMux.httpConn != nil {
			ch = pMux.httpConn
			readMore = true
			//logs.Debug("Only use httpConn")
		} else if pMux.managerConn != nil {
			ch = pMux.managerConn
			readMore = true
			//logs.Debug("Only use managerConn")
		} else if pMux.clientWsConn != nil {
			ch = pMux.clientWsConn
			readMore = true
			//logs.Debug("Only use clientWsConn")
		} else {
			return
		}
	case CLIENT: // client connection
		if pMux.clientConn == nil {
			return
		}
		ch = pMux.clientConn
	default: // https or clientTls or clientWss
		if pMux.httpsConn != nil && pMux.clientTlsConn != nil {
			helloInfo, rawData, err := crypt.ReadClientHello(conn, buf)
			if err == nil && helloInfo != nil && (helloInfo.ServerName == "" || helloInfo.ServerName == pMux.clientHost) {
				ch = pMux.clientTlsConn
				//logs.Debug("Use clientTlsConn")
			} else {
				ch = pMux.httpsConn
				//logs.Debug("Use httpsConn")
			}
			rs = rawData
		} else if pMux.httpsConn != nil {
			ch = pMux.httpsConn
			//logs.Debug("Only use httpsConn")
		} else if pMux.clientTlsConn != nil {
			ch = pMux.clientTlsConn
			//logs.Debug("Only use clientTlsConn")
		} else if pMux.clientWssConn != nil {
			ch = pMux.clientWssConn
			//logs.Debug("Only use clientWssConn")
		} else {
			return
		}
		readMore = true
	}
	if len(rs) == 0 {
		rs = buf
	}
	timer := time.NewTimer(ACCEPT_TIME_OUT)
	select {
	case <-timer.C:
	case ch <- newPortConn(conn, rs, readMore):
	}
}

func (pMux *PortMux) Close() error {
	if pMux.isClose {
		return errors.New("the port pmux has closed")
	}
	pMux.isClose = true
	close(pMux.clientConn)
	close(pMux.clientTlsConn)
	close(pMux.httpsConn)
	close(pMux.httpConn)
	close(pMux.managerConn)
	return pMux.Listener.Close()
}

func (pMux *PortMux) GetClientListener() net.Listener {
	pMux.clientConn = make(chan *PortConn)
	return NewPortListener(pMux.clientConn, pMux.Listener.Addr())
}

func (pMux *PortMux) GetClientTlsListener() net.Listener {
	pMux.clientTlsConn = make(chan *PortConn)
	return NewPortListener(pMux.clientTlsConn, pMux.Listener.Addr())
}

func (pMux *PortMux) GetClientWsListener() net.Listener {
	pMux.clientWsConn = make(chan *PortConn)
	return NewPortListener(pMux.clientWsConn, pMux.Listener.Addr())
}

func (pMux *PortMux) GetClientWssListener() net.Listener {
	pMux.clientWssConn = make(chan *PortConn)
	return NewPortListener(pMux.clientWssConn, pMux.Listener.Addr())
}

func (pMux *PortMux) GetHttpListener() net.Listener {
	pMux.httpConn = make(chan *PortConn)
	return NewPortListener(pMux.httpConn, pMux.Listener.Addr())
}

func (pMux *PortMux) GetHttpsListener() net.Listener {
	pMux.httpsConn = make(chan *PortConn)
	return NewPortListener(pMux.httpsConn, pMux.Listener.Addr())
}

func (pMux *PortMux) GetManagerListener() net.Listener {
	pMux.managerConn = make(chan *PortConn)
	return NewPortListener(pMux.managerConn, pMux.Listener.Addr())
}
