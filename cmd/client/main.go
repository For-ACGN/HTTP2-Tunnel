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

	"github.com/For-ACGN/HTTP2-Tunnel"
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

func warn(reason string) {
	fmt.Println()
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Println("!!!                                           !!!")
	fmt.Println("!!!   WARNING: MAN-IN-THE-MIDDLE ATTACK       !!!")
	fmt.Println("!!!   DETECTED - CONNECTION TERMINATED        !!!")
	fmt.Println("!!!                                           !!!")
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Println()
	fmt.Println("  A potential MITM attack was detected when connecting to the server.")
	fmt.Println("  The connection has been terminated to protect your data.")
	fmt.Println()
	fmt.Println("  Reason:", reason)
	fmt.Println()
	fmt.Println("  Possible causes:")
	fmt.Println("    - A network intermediary is intercepting TLS")
	fmt.Println("    - The server certificate has been replaced")
	fmt.Println("    - A proxy or firewall is tampering with the connection")
	fmt.Println()
	fmt.Println("  Recommended actions:")
	fmt.Println("    - Do NOT trust this connection")
	fmt.Println("    - Verify your network environment")
	fmt.Println("    - Check if a VPN or proxy is active")
	fmt.Println("    - Contact your network administrator")
	fmt.Println()
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

	var config h2tunnel.ClientConfig
	err = decoder.Decode(&config)
	checkError(err)

	// read Root CA file if it exists
	rootCA := config.Client.RootCA
	if rootCA != "" {
		ca, err := os.ReadFile(rootCA) // #nosec
		checkError(err)
		config.Client.RootCA = string(ca)
	}

	// create client from config
	client, err := h2tunnel.NewClient(&config)
	checkError(err)

	// detect the server has been hijacked.
	logger := log.New(os.Stdout, "", log.LstdFlags)
	var reached bool
	for i := 0; i < 3; i++ {
		hijacked, err := client.Detect()
		if err != nil {
			if hijacked {
				warn(err.Error())
				os.Exit(1)
			}
			logger.Println("[error]", err)
			continue
		} else {
			reached = true
			break
		}
	}
	if !reached {
		logger.Println("[error] the server cannot be reached")
		err = client.Close()
		checkError(err)
		return
	}

	// start core workers
	client.Start()
	time.Sleep(250 * time.Millisecond)

	// client.Login() will use 3-RTT, the time is similar as
	// connect latency when connect a target with HTTPS(TLS 1.3)
	now := time.Now()
	err = client.Login()
	checkError(err)
	latency := time.Since(now).Milliseconds()
	logger.Printf("[info] connect latency: %dms\n", latency)

	// give some time for pre-connection
	time.Sleep(time.Second)
	client.Serve()

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
