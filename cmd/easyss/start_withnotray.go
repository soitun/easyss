//go:build with_notray

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/nange/easyss"
	log "github.com/sirupsen/logrus"
)

func StartEasyss(ss *easyss.Easyss) {
	if err := ss.InitTcpPool(); err != nil {
		log.Errorf("init tcp pool error:%v", err)
	}

	go ss.LocalSocks5() // start local server
	go ss.LocalHttp()   // start local http proxy server

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Kill, os.Interrupt, syscall.SIGINT, syscall.SIGTERM,
		syscall.SIGQUIT)

	log.Infof("got signal to exit: %v", <-c)
}