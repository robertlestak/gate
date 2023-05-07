package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/robertlestak/gate/pkg/gate"
	"github.com/robertlestak/gate/pkg/keys"
	"github.com/robertlestak/memory/pkg/memory"
	log "github.com/sirupsen/logrus"
)

var (
	Version       = "dev"
	gateFlags     = flag.NewFlagSet("gate", flag.ExitOnError)
	upstreamFlags = flag.NewFlagSet("gate upstream", flag.ExitOnError)
)

func init() {
	ll, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
}

func cleanSplitString(s string) []string {
	var r []string
	for _, v := range strings.Split(s, ",") {
		ss := strings.TrimSpace(v)
		if ss != "" {
			r = append(r, ss)
		}
	}
	return r
}

func upstreamUsage() {
	fmt.Println("Usage: gate upstream [OPTIONS] COMMAND")
	upstreamFlags.PrintDefaults()
	fmt.Println("Commands:")
	fmt.Println("  register")
	fmt.Println("  deregister")
	os.Exit(0)
}

func upstream() {
	l := log.WithFields(log.Fields{
		"fn": "upstream",
	})
	l.Debug("Starting upstream")
	upstreamFlags = flag.NewFlagSet("gate upstream", flag.ExitOnError)
	external := upstreamFlags.String("external", "", "External domain to register")
	internal := upstreamFlags.String("internal", "", "Internal domain to register")
	port := upstreamFlags.Int("port", 443, "Port to register")
	timeout := upstreamFlags.String("timeout", "5m", "Timeout to register")
	rateLimit := upstreamFlags.Int("rate-limit", 0, "Rate limit per second to register, 0 for no limit")
	allowCidrs := upstreamFlags.String("allow-cidrs", "", "Comma separated list of CIDRs to allow")
	denyCidrs := upstreamFlags.String("deny-cidrs", "", "Comma separated list of CIDRs to deny")
	keyFile := upstreamFlags.String("key", "", "Path to private key file")
	gateServer := upstreamFlags.String("gate", "", "Gate server to register with")
	registrationKey := upstreamFlags.String("registration-key", "", "Registration key")
	tlsCa := upstreamFlags.String("tls-ca", "", "Path to TLS CA")
	tlsCert := upstreamFlags.String("tls-cert", "", "Path to TLS cert")
	tlsKey := upstreamFlags.String("tls-key", "", "Path to TLS key")
	tlsInsecure := upstreamFlags.Bool("tls-insecure", false, "Skip TLS verification")
	configFile := upstreamFlags.String("config", "", "Path to config file")
	upstreamFlags.Usage = upstreamUsage
	upstreamFlags.Parse(gateFlags.Args()[1:])
	upstreamCmd := upstreamFlags.Arg(0)
	u := &gate.Upstream{
		ExternalHost: *external,
		InternalHost: *internal,
		Port:         *port,
		RateLimit:    *rateLimit,
		AllowCidrs:   cleanSplitString(*allowCidrs),
		DenyCidrs:    cleanSplitString(*denyCidrs),
	}
	gc := &gate.GateServerConfig{
		Server: *gateServer,
		TLS: gate.GateServerConfigTls{
			CA:       *tlsCa,
			Cert:     *tlsCert,
			Key:      *tlsKey,
			Insecure: *tlsInsecure,
		},
	}
	t, err := time.ParseDuration(*timeout)
	if err != nil {
		l.WithError(err).Error("Failed to parse timeout")
		os.Exit(1)
	}
	u.Timeout = t
	gc.RegistrationKey = os.ExpandEnv(*registrationKey)
	if *configFile != "" {
		c := &gate.Config{}
		if err := c.LoadFile(*configFile); err != nil {
			l.WithError(err).Error("Failed to load config file")
			os.Exit(1)
		}
		u = c.Upstream
		gc = c.Server
		if c.KeyFile != "" {
			keyFile = &c.KeyFile
		}
		if u.ExternalHost == "" {
			u.ExternalHost = *external
		}
		if u.InternalHost == "" {
			u.InternalHost = *internal
		}
		if u.Port == 0 {
			u.Port = *port
		}
		if u.Timeout == 0 {
			u.Timeout = t
		}
		if u.RateLimit == 0 {
			u.RateLimit = *rateLimit
		}
		if gc.TLS.CA == "" {
			gc.TLS.CA = *tlsCa
		}
		if gc.TLS.Cert == "" {
			gc.TLS.Cert = *tlsCert
		}
		if gc.TLS.Key == "" {
			gc.TLS.Key = *tlsKey
		}
		if !gc.TLS.Insecure {
			gc.TLS.Insecure = *tlsInsecure
		}
		if gc.RegistrationKey == "" {
			gc.RegistrationKey = *registrationKey
		}
		if len(u.AllowCidrs) == 0 {
			u.AllowCidrs = cleanSplitString(*allowCidrs)
		}
		if len(u.DenyCidrs) == 0 {
			u.DenyCidrs = cleanSplitString(*denyCidrs)
		}
	}
	gc.RegistrationKey = os.ExpandEnv(gc.RegistrationKey)
	if *keyFile == "" {
		l.Error("Must specify key file")
		os.Exit(1)
	}
	fd, err := os.ReadFile(*keyFile)
	if err != nil {
		l.WithError(err).Error("Failed to read key file")
		os.Exit(1)
	}
	key, err := keys.BytesToPrivateKey(fd)
	if err != nil {
		l.WithError(err).Error("Failed to get private key")
		os.Exit(1)
	}
	publicKeyPem, err := keys.PrivateKeyToPublicPem(key)
	if err != nil {
		l.WithError(err).Error("Failed to get public key pem")
		os.Exit(1)
	}
	u.AdminCert = publicKeyPem
	if u.ExternalHost == "" && u.InternalHost != "" {
		u.ExternalHost = u.InternalHost
	}
	if u.InternalHost == "" && u.ExternalHost != "" {
		u.InternalHost = u.ExternalHost
	}
	if u.ExternalHost == "" || u.InternalHost == "" {
		l.Error("Must specify external and internal domains")
		os.Exit(1)
	}
	if upstreamCmd == "" {
		l.Error("Must specify client command")
		os.Exit(1)
	}
	switch upstreamCmd {
	case "register":
		if err := u.RegisterWithGate(key, gc); err != nil {
			l.WithError(err).Error("Failed to register with gate")
			os.Exit(1)
		}
	case "deregister":
		if err := u.DeregisterWithGate(key, gc); err != nil {
			l.WithError(err).Error("Failed to deregister with gate")
			os.Exit(1)
		}
	default:
		l.Error("Unknown client command: ", upstreamCmd)
		os.Exit(1)
	}
}

func server() {
	l := log.WithFields(log.Fields{
		"fn": "server",
	})
	l.Debug("Starting server")
	serverFlags := flag.NewFlagSet("gate server", flag.ExitOnError)
	port := serverFlags.Int("port", 443, "Port to listen on")
	plaintextPort := serverFlags.Int("plaintext-port", 80, "Port to listen on for plaintext")
	adminPort := serverFlags.Int("admin-port", 4443, "Port to listen on for admin")
	tlsCa := serverFlags.String("tls-ca", "", "Path to TLS CA")
	tlsCert := serverFlags.String("tls-cert", "", "Path to TLS cert")
	tlsKey := serverFlags.String("tls-key", "", "Path to TLS key")
	clientAuth := serverFlags.Bool("tls-client-auth", false, "Require client auth")
	memoryBackendStr := serverFlags.String("memory-backend", "memory", "Memory backend type. Options: memory, redis")
	memoryBackendConfig := serverFlags.String("memory-config", "", "Memory backend config as JSON string")
	memoryKey := serverFlags.String("memory-key", "", "Memory key")
	memoryGenerateKey := serverFlags.Bool("memory-gen-key", false, "Generate memory key")
	memoryRemoveKey := serverFlags.Bool("memory-rm-key", false, "Remove memory key")
	registrationKey := serverFlags.String("registration-key", "", "Registration key")
	serverFlags.Parse(gateFlags.Args()[1:])
	memoryBackend := memory.BackendType(*memoryBackendStr)
	var key *rsa.PrivateKey
	var err error
	if *memoryGenerateKey {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		key, err = memory.ReadKey(memoryKey, *memoryRemoveKey)
		if err != nil {
			log.Fatal(err)
		}
	}
	var cfg map[string]any
	if *memoryBackendConfig != "" {
		if err := json.Unmarshal([]byte(*memoryBackendConfig), &cfg); err != nil {
			l.WithError(err).Error("Failed to unmarshal memory backend config")
			os.Exit(1)
		}
	}
	if err := memory.New(memoryBackend, cfg, key); err != nil {
		l.WithError(err).Error("Failed to init memory backend")
		os.Exit(1)
	}
	go func() {
		if err := gate.Start(*port); err != nil {
			l.WithError(err).Error("Failed to start gate")
			os.Exit(1)
		}
	}()
	go func() {
		if err := gate.StartTLSRedirect(*plaintextPort); err != nil {
			l.WithError(err).Error("Failed to start gate TLS redirect")
			os.Exit(1)
		}
	}()
	go func() {
		gate.RegistrationKey = os.ExpandEnv(*registrationKey)
		if err := gate.StartAdminServer(*adminPort, *tlsCa, *tlsCert, *tlsKey, *clientAuth); err != nil {
			l.WithError(err).Error("Failed to start gate admin server")
			os.Exit(1)
		}
	}()
	select {}
}

func printVersion() {
	fmt.Println("gate version:", Version)
}

func usage() {
	fmt.Println("Usage: gate [OPTIONS] COMMAND")
	gateFlags.PrintDefaults()
	fmt.Println("Commands:")
	fmt.Println("  upstream [OPTIONS] COMMAND")
	fmt.Println("  server [OPTIONS]")
	os.Exit(0)
}

func main() {
	gateFlags = flag.NewFlagSet("gate", flag.ExitOnError)
	logLevel := gateFlags.String("log-level", log.GetLevel().String(), "Log level")
	version := gateFlags.Bool("version", false, "Print version")
	gateFlags.Usage = usage
	gateFlags.Parse(os.Args[1:])
	if *version {
		printVersion()
		os.Exit(0)
	}
	ll, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.WithError(err).Error("Failed to parse log level")
		os.Exit(1)
	}
	log.SetLevel(ll)
	l := log.WithFields(log.Fields{
		"fn": "main",
	})
	l.Debug("Starting gate")
	if len(gateFlags.Args()) == 0 {
		l.Error("Must specify server or upstream")
		os.Exit(1)
	}
	switch gateFlags.Args()[0] {
	case "upstream":
		upstream()
	case "server":
		server()
	default:
		l.Error("Must specify server or upstream")
		os.Exit(1)
	}
}
