package goroutine

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mycoool/nps/lib/common"
	"github.com/mycoool/nps/lib/file"
	"github.com/mycoool/nps/lib/logs"
	"github.com/panjf2000/ants/v2"
)

type connGroup struct {
	src    io.ReadWriteCloser
	dst    io.ReadWriteCloser
	wg     *sync.WaitGroup
	n      *int64
	flows  []*file.Flow
	task   *file.Tunnel
	remote string
}

func newConnGroup(dst, src io.ReadWriteCloser, wg *sync.WaitGroup, n *int64, flows []*file.Flow, task *file.Tunnel, remote string) connGroup {
	return connGroup{
		src:    src,
		dst:    dst,
		wg:     wg,
		n:      n,
		flows:  flows,
		task:   task,
		remote: remote,
	}
}

func CopyBuffer(dst io.Writer, src io.Reader, flows []*file.Flow, task *file.Tunnel, remote string) (written int64, err error) {
	buf := common.CopyBuff.Get()
	defer common.CopyBuff.Put(buf)

	checkedHTTP := false
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if task != nil && !checkedHTTP {
				checkedHTTP = true
				firstLine := string(buf[:nr])
				if len(firstLine) > 3 {
					method := firstLine[:3]
					if method == "HTT" || method == "GET" || method == "POS" || method == "HEA" || method == "PUT" || method == "DEL" {
						if method != "HTT" {
							heads := strings.Split(firstLine, "\r\n")
							if len(heads) >= 2 {
								logs.Info("HTTP Request method %s, %s, remote address %s, target %s", heads[0], heads[1], remote, task.Target.TargetStr)
							}
						}
						task.IsHttp = true
					} else {
						task.IsHttp = false
					}
				}
			}
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				if len(flows) > 0 {
					nw64 := int64(nw)
					for _, f := range flows {
						if f == nil {
							continue
						}
						f.Add(nw64, nw64)
						if f.FlowLimit > 0 && (f.FlowLimit<<20) < (f.ExportFlow+f.InletFlow) {
							logs.Info("Flow limit exceeded")
							return written, errors.New("Flow limit exceeded")
						}
						if !f.TimeLimit.IsZero() && f.TimeLimit.Before(time.Now()) {
							logs.Info("Time limit exceeded")
							return written, errors.New("Time limit exceeded")
						}
					}
				}
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

func copyConnGroup(group interface{}) {
	cg, ok := group.(connGroup)
	if !ok {
		return
	}
	var err error
	*cg.n, err = CopyBuffer(cg.dst, cg.src, cg.flows, cg.task, cg.remote)
	if err != nil {
		cg.src.Close()
		cg.dst.Close()
	}
	cg.wg.Done()
}

type Conns struct {
	conn1 io.ReadWriteCloser // mux connection
	conn2 net.Conn           // outside connection
	flows []*file.Flow       // support multiple flows
	wg    *sync.WaitGroup
	task  *file.Tunnel
}

func NewConns(c1 io.ReadWriteCloser, c2 net.Conn, flows []*file.Flow, wg *sync.WaitGroup, task *file.Tunnel) Conns {
	return Conns{
		conn1: c1,
		conn2: c2,
		flows: flows,
		wg:    wg,
		task:  task,
	}
}

func copyConns(group interface{}) {
	conns := group.(Conns)
	wg := new(sync.WaitGroup)
	wg.Add(2)
	var in, out int64
	remoteAddr := conns.conn2.RemoteAddr().String()
	_ = connCopyPool.Invoke(newConnGroup(conns.conn1, conns.conn2, wg, &in, conns.flows, conns.task, remoteAddr))
	_ = connCopyPool.Invoke(newConnGroup(conns.conn2, conns.conn1, wg, &out, conns.flows, conns.task, remoteAddr))
	wg.Wait()
	if conns.task != nil {
		if conns.task.Flow != nil {
			conns.task.Flow.Sub(out, in)
		}
	}
	conns.wg.Done()
}

var connCopyPool, _ = ants.NewPoolWithFunc(200000, copyConnGroup, ants.WithNonblocking(false))
var CopyConnsPool, _ = ants.NewPoolWithFunc(100000, copyConns, ants.WithNonblocking(false))

func Join(c1, c2 net.Conn, flows []*file.Flow, task *file.Tunnel, remote string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		if _, err := CopyBuffer(c1, c2, flows, task, remote); err != nil {
			c1.Close()
			c2.Close()
		}
		wg.Done()
	}()
	go func() {
		if _, err := CopyBuffer(c2, c1, flows, task, remote); err != nil {
			c1.Close()
			c2.Close()
		}
		wg.Done()
	}()
	wg.Wait()
}
