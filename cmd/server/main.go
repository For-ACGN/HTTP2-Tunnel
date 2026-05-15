package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/HTTP2-Tunnel"
)

var (
	cfgPath string
	setCap  bool
)

func init() {
	flag.StringVar(&cfgPath, "cfg", "config.toml", "set configuration file path")
	flag.BoolVar(&setCap, "sc", false, "set cap_net_bind_service, ACME mode need this on Linux")
	flag.Parse()
}

func main() {
	if setCap {
		if runtime.GOOS == "windows" {
			return
		}
		path, err := os.Executable()
		checkError(err)
		cmd := exec.Command("setcap", "cap_net_bind_service=+ep", path) // #nosec
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		checkError(err)
		return
	}

	// read ServerConfig from config file
	cfgData, err := os.ReadFile(cfgPath) // #nosec
	checkError(err)
	decoder := toml.NewDecoder(bytes.NewReader(cfgData))
	decoder.DisallowUnknownFields()

	var config h2tunnel.ServerConfig
	err = decoder.Decode(&config)
	checkError(err)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	server, err := h2tunnel.NewServer(ctx, &config)
	checkError(err)

	fmt.Println("calculate certificate public key hash")
	list, err := server.CertPinning(ctx)
	checkError(err)
	for _, item := range list {
		fmt.Printf("%X\n", item)
	}

	go func() {
		err := server.Serve()
		checkError(err)
	}()

	<-signalCh

	err = server.Close()
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
