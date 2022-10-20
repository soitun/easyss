package easyss

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/nange/easypool"
	log "github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
)

const version = "1.3.0"

func PrintVersion() {
	fmt.Println("easyss version", version)
}

type Statistics struct {
	BytesSend   int64
	BytesRecive int64
}

type Easyss struct {
	config  *Config
	tcpPool easypool.Pool
	stat    *Statistics

	socksServer     *socks5.Server
	httpProxyServer *http.Server
}

func New(config *Config) *Easyss {
	ss := &Easyss{
		config: config,
		stat:   &Statistics{},
	}
	go ss.printStatistics()

	return ss
}

func (ss *Easyss) InitTcpPool() error {
	factory := func() (net.Conn, error) {
		return tls.Dial("tcp", fmt.Sprintf("%s:%d", ss.config.Server, ss.config.ServerPort), nil)
	}
	config := &easypool.PoolConfig{
		InitialCap:  10,
		MaxCap:      50,
		MaxIdle:     10,
		Idletime:    5 * time.Minute,
		MaxLifetime: 30 * time.Minute,
		Factory:     factory,
	}
	tcpPool, err := easypool.NewHeapPool(config)
	ss.tcpPool = tcpPool
	return err
}

func (ss *Easyss) LocalPort() int {
	return ss.config.LocalPort
}

func (ss *Easyss) ServerPort() int {
	return ss.config.ServerPort
}

func (ss *Easyss) LocalAddr() string {
	return fmt.Sprintf("%s:%d", "127.0.0.1", ss.LocalPort())
}

func (ss *Easyss) BindAll() bool {
	return ss.config.BindALL
}

func (ss *Easyss) Server() string {
	return fmt.Sprintf("%s:%d", ss.config.Server, ss.config.ServerPort)
}

func (ss *Easyss) UpdateConfig(config *Config) bool {
	ss.config = config
	return true
}

func (ss *Easyss) Close() {
	if ss.tcpPool != nil {
		ss.tcpPool.Close()
		ss.tcpPool = nil
	}
	if ss.httpProxyServer != nil {
		ss.httpProxyServer.Close()
		ss.httpProxyServer = nil
	}
	if ss.socksServer != nil {
		ss.socksServer.Shutdown()
		ss.socksServer = nil
	}
}

func (ss *Easyss) printStatistics() {
	for {
		select {
		case <-time.After(time.Minute):
			sendSize := atomic.LoadInt64(&ss.stat.BytesSend) / (1024 * 1024)
			reciveSize := atomic.LoadInt64(&ss.stat.BytesRecive) / (1024 * 1024)
			log.Debugf("easyss send data size: %vMB, recive data size: %vMB", sendSize, reciveSize)
		}
	}
}
