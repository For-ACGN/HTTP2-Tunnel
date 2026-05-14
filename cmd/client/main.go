package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/MIX-Socks"
)

var (
	cfgPath  string
	password string
)

func init() {
	flag.StringVar(&cfgPath, "cfg", "config.toml", "set configuration file path")
	flag.StringVar(&password, "ph", "", "calculate password hash for config")
	flag.Parse()
}

func main() {
	if password != "" {
		h := sha256.Sum256([]byte(password))
		fmt.Println(hex.EncodeToString(h[:]))
		return
	}

	// read ClientConfig from config file
	cfgData, err := os.ReadFile(cfgPath) // #nosec
	checkError(err)
	decoder := toml.NewDecoder(bytes.NewReader(cfgData))
	decoder.DisallowUnknownFields()

	var config msocks.ClientConfig
	err = decoder.Decode(&config)
	checkError(err)

	// read Root CA file if it exists
	rootCA := config.Server.RootCA
	if rootCA != "" {
		ca, err := os.ReadFile(rootCA) // #nosec
		checkError(err)
		config.Server.RootCA = string(ca)
	}

	// create client from config
	client, err := msocks.NewClient(&config)
	checkError(err)

	// check the server can be reached
	var reached bool
	for i := 0; i < 3; i++ {
		err = client.Check()
		if err != nil {
			fmt.Println(err)
			continue
		} else {
			reached = true
			break
		}
	}
	if !reached {
		fmt.Println("the server cannot be reached")
		err = client.Close()
		checkError(err)
		return
	}

	// start core workers
	go func() {
		err := client.Serve()
		checkError(err)
	}()

	// give some time for the connector
	time.Sleep(time.Second)

	// client.Login() will use 3-RTT, the time is similar as
	// connect latency when connect a target with HTTPS(TLS 1.3)
	go func() {
		now := time.Now()
		err = client.Login()
		checkError(err)
		latency := time.Since(now).Milliseconds()
		logger := log.New(os.Stdout, "", log.LstdFlags)
		logger.Printf("[info] connect latency: %dms\n", latency)
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	<-signalCh

	err = client.Logout()
	checkError(err)
	err = client.Close()
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
