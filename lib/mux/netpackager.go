package mux

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/mycoool/nps/lib/logs"
)

type basePackager struct {
	buf []byte
	// buf contain the mux protocol struct binary data, we copy data to buf firstly.
	// replace binary.Read/Write method, it may use reflect shows slowly.
	// also reduce Conn.Read/Write calls which use syscall.
	// due to our test, Conn.Write method reduce by two-thirds CPU times,
	// Conn.Write method has 20% reduction of the CPU times,
	// totally provides more than twice of the CPU performance improvement.
	length  uint16
	content []byte
}

// Set 设置数据包内容
// 将内容复制到缓冲区或content字段
//
// 参数:
//
//	content: 待设置的数据内容
//
// 返回:
//
//	error: 错误信息（内容过大或缓冲区太小）
func (Self *basePackager) Set(content []byte) (err error) {
	Self.reset()

	if content == nil {
		logs.Error("mux:packer: new pack content is nil")
		return
		//panic("mux:packer: new pack content is nil")
	}

	n := len(content)
	if n > maximumSegmentSize {
		logs.Error("mux:packer: new pack content segment too large")
		return
	}

	if Self.content == nil {
		if cap(Self.buf) < 7+n {
			logs.Error("mux:packer: buf too small")
			return
		}
		copy(Self.buf[7:7+n], content)
	} else {
		if cap(Self.content) < n {
			logs.Error("mux:packer: buf too small")
			return
		}
		copy(Self.content[:n], content)
	}
	Self.length = uint16(n)
	return
}

// GetContent 获取数据包内容
// 从缓冲区或content字段中读取数据
//
// 返回:
//
//	[]byte: 数据内容
//	error: 错误信息（内容为空时返回错误）
func (Self *basePackager) GetContent() (content []byte, err error) {
	if Self.length == 0 || (Self.content == nil && Self.buf == nil) {
		return nil, errors.New("mux:packer:content is nil")
	}
	if Self.content == nil {
		return Self.buf[7 : 7+Self.length], nil
	}
	return Self.content[:Self.length], nil
}

// Pack 将数据包序列化为二进制并写入到输出流
// 写入格式：[length(2字节)] + [content(length字节)]
//
// 参数:
//
//	writer: 输出流（如网络连接）
//
// 返回:
//
//	error: 写入错误
func (Self *basePackager) Pack(writer io.Writer) (err error) {
	binary.LittleEndian.PutUint16(Self.buf[5:7], Self.length)
	if Self.content == nil {
		_, err = writer.Write(Self.buf[:7+Self.length])
	} else {
		_, err = writer.Write(Self.buf[:7])
		if err != nil {
			return
		}
		_, err = writer.Write(Self.content[:Self.length])
	}
	return
}

// UnPack 从输入流读取并解析数据包
// 读取格式：[length(2字节)] + [content(length字节)]
//
// 参数:
//
//	reader: 输入流（如网络连接）
//
// 返回:
//
//	uint16: 读取的总字节数
//	error: 读取错误
func (Self *basePackager) UnPack(reader io.Reader) (n uint16, err error) {
	Self.reset()
	l, err := io.ReadFull(reader, Self.buf[5:7])
	if err != nil {
		return
	}
	n += uint16(l)
	Self.length = binary.LittleEndian.Uint16(Self.buf[5:7])

	if int(Self.length) > maximumSegmentSize {
		err = errors.New("mux:packer: unpack content segment too large")
		return
	}

	if Self.content == nil {
		if cap(Self.buf) < 7+int(Self.length) {
			err = errors.New("mux:packer: unpack err, content length too large")
			return
		}
		l, err = io.ReadFull(reader, Self.buf[7:7+Self.length])
	} else {
		if int(Self.length) > cap(Self.content) {
			err = errors.New("mux:packer: unpack err, content length too large")
			return
		}
		l, err = io.ReadFull(reader, Self.content[:Self.length])
	}

	n += uint16(l)
	return
}

// reset 重置数据包状态
// 清空长度和内容，准备下一次使用
func (Self *basePackager) reset() {
	Self.length = 0
	//Self.content = nil
	//Self.buf = nil
}

// muxPackager MUX协议的数据包处理器
// 支持多种消息类型和流量控制机制
type muxPackager struct {
	flag         uint8  // 消息类型标志（muxPingFlag、muxNewMsg等）
	id           int32  // 消息ID
	window       uint64 // 流控窗口大小
	priority     bool   // 是否为高优先级消息
	basePackager        // 继承基础数据包处理器
}

// Set 设置MUX数据包内容
// 根据消息类型设置不同的内容格式
//
// 参数:
//
//	flag: 消息类型标志
//	id: 消息ID
//	content: 消息内容（类型根据flag而不同）
//
// 返回:
//
//	error: 错误信息
func (Self *muxPackager) Set(flag uint8, id int32, content interface{}) (err error) {
	Self.buf = windowBuff.Get()
	Self.flag = flag
	Self.id = id
	switch flag {
	case muxPingFlag, muxPingReturn, muxNewMsg, muxNewMsgPart:
		//Self.content = windowBuff.Get()
		if content != nil {
			err = Self.basePackager.Set(content.([]byte))
		}
	case muxMsgSendOk:
		// MUX_MSG_SEND_OK contains one data
		Self.window = content.(uint64)
	default:
	}
	return
}

// Pack 将MUX数据包序列化为二进制并写入到输出流
// 写入格式根据消息类型而不同：
// - 普通消息：[flag(1)] + [id(4)] + [length(2)] + [content(length)]
// - 流控消息：[flag(1)] + [id(4)] + [window(8)]
//
// 参数:
//
//	writer: 输出流
//
// 返回:
//
//	error: 写入错误
func (Self *muxPackager) Pack(writer io.Writer) (err error) {
	//Self.buf = Self.buf[0:13]
	Self.buf[0] = Self.flag
	binary.LittleEndian.PutUint32(Self.buf[1:5], uint32(Self.id))
	switch Self.flag {
	case muxNewMsg, muxNewMsgPart, muxPingFlag, muxPingReturn:
		err = Self.basePackager.Pack(writer)
		if Self.content != nil {
			windowBuff.Put(Self.content)
			Self.content = nil
		}
	case muxMsgSendOk:
		binary.LittleEndian.PutUint64(Self.buf[5:13], Self.window)
		_, err = writer.Write(Self.buf[:13])
	default:
		_, err = writer.Write(Self.buf[:5])
	}
	windowBuff.Put(Self.buf)
	Self.buf = nil
	return
}

// UnPack 从输入流读取并解析MUX数据包
// 根据消息类型读取不同的内容格式
//
// 参数:
//
//	reader: 输入流
//
// 返回:
//
//	uint16: 读取的总字节数
//	error: 读取错误
func (Self *muxPackager) UnPack(reader io.Reader) (n uint16, err error) {
	Self.buf = windowBuff.Get()
	//Self.buf = Self.buf[0:13]
	l, err := io.ReadFull(reader, Self.buf[:5])
	if err != nil {
		windowBuff.Put(Self.buf)
		Self.buf = nil
		return
	}
	n += uint16(l)
	Self.flag = Self.buf[0]
	Self.id = int32(binary.LittleEndian.Uint32(Self.buf[1:5]))
	switch Self.flag {
	case muxNewMsg, muxNewMsgPart, muxPingFlag, muxPingReturn:
		var m uint16
		Self.content = windowBuff.Get() // need Get a window buf from pool
		m, err = Self.basePackager.UnPack(reader)
		n += m
	case muxMsgSendOk:
		l, err = io.ReadFull(reader, Self.buf[5:13])
		if err == nil {
			Self.window = binary.LittleEndian.Uint64(Self.buf[5:13])
			n += uint16(l) // uint64
		}
	default:
	}
	windowBuff.Put(Self.buf)
	Self.buf = nil
	return
}

// reset 重置MUX数据包状态
// 清空所有字段，准备下一次使用
// 归还缓冲区到对象池
func (Self *muxPackager) reset() {
	Self.id = 0
	Self.flag = 0
	Self.length = 0
	Self.content = nil
	Self.window = 0
	if Self.buf != nil {
		windowBuff.Put(Self.buf)
	}
	Self.buf = nil
}
