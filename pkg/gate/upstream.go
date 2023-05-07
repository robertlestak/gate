package gate

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/robertlestak/gate/pkg/keys"
	"github.com/robertlestak/gate/pkg/rate"
	"github.com/robertlestak/memory/pkg/memory"
	log "github.com/sirupsen/logrus"
)

var (
	RegistrationKey        string
	RegisterTypeRegister   UpstreamRegistrationType = "register"
	RegisterTypeDeregister UpstreamRegistrationType = "deregister"
)

type UpstreamRegistrationType string

type UpstreamRegistrationRequest struct {
	Type            UpstreamRegistrationType `json:"type"`
	RegistrationKey string                   `json:"registrationKey"`
	Upstream        *Upstream                `json:"upstream"`
	Payload         []byte                   `json:"payload"`
	Signature       []byte                   `json:"signature"`
}

type UpstreamRegistrationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type GateServerConfigTls struct {
	CA       string `json:"ca" yaml:"ca"`
	Cert     string `json:"cert" yaml:"cert"`
	Key      string `json:"key" yaml:"key"`
	Insecure bool   `json:"insecure" yaml:"insecure"`
}

type GateServerConfig struct {
	Server          string              `json:"server" yaml:"server"`
	RegistrationKey string              `json:"registrationKey" yaml:"registrationKey"`
	TLS             GateServerConfigTls `json:"tls" yaml:"tls"`
}

type Upstream struct {
	ExternalHost string        `json:"external" yaml:"external"`
	InternalHost string        `json:"internal" yaml:"internal"`
	Port         int           `json:"port" yaml:"port"`
	Timeout      time.Duration `json:"timeout" yaml:"timeout"`
	RateLimit    int           `json:"rateLimit" yaml:"rateLimit"`
	AllowCidrs   []string      `json:"AllowCidrs" yaml:"AllowCidrs"`
	DenyCidrs    []string      `json:"DenyCidrs" yaml:"DenyCidrs"`

	AdminCert []byte `json:"adminCert" yaml:"adminCert"`

	// filled by client when registering with gate
	RequestTime time.Time `json:"requestTime" yaml:"requestTime"`
}

func (u *Upstream) Validate() error {
	l := log.WithFields(log.Fields{
		"fn": "Validate",
	})
	l.Debug("Validating upstream")
	if u.ExternalHost == "" {
		return fmt.Errorf("external host cannot be empty")
	}
	if u.InternalHost == "" {
		return fmt.Errorf("internal host cannot be empty")
	}
	if u.Port == 0 {
		return fmt.Errorf("port cannot be 0")
	}
	if u.Timeout == 0 {
		return fmt.Errorf("timeout cannot be 0")
	}
	return nil
}

func (u *Upstream) TestConnection() error {
	l := log.WithFields(log.Fields{
		"fn": "TestConnection",
	})
	l.Debug("Testing connection")
	// connect to upstream and try to create a TLS connection
	// if it fails, return error
	ctx, cancel := context.WithTimeout(context.Background(), u.Timeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", u.InternalHost, u.Port))
	if err != nil {
		l.WithError(err).Error("Failed to dial upstream")
		return err
	}
	defer conn.Close()
	// create tls connection, using the external host as the SNI
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: u.ExternalHost,
	})
	if err := tlsConn.Handshake(); err != nil {
		l.WithError(err).Error("Failed to handshake with upstream")
		return err
	}
	return nil
}

func (u *Upstream) IsAllowed(ip string) bool {
	l := log.WithFields(log.Fields{
		"fn": "IsAllowed",
	})
	l.Debug("Checking if ip is allowed")
	if u.RateLimit > 0 {
		if err := rate.HandleOriginRequest(u.ExternalHost, u.RateLimit); err != nil {
			l.WithError(err).Error("Failed to handle origin request")
			return false
		}
	}
	if len(u.AllowCidrs) > 0 {
		for _, a := range u.AllowCidrs {
			// check if ip is in cidr
			_, cidr, err := net.ParseCIDR(a)
			if err != nil {
				l.WithError(err).Error("Failed to parse cidr")
				return false
			}
			if cidr.Contains(net.ParseIP(ip)) {
				l.Debug("IP is allowed")
				return true
			}
		}
		l.Debug("IP is not allowed")
		return false
	}
	if len(u.DenyCidrs) > 0 {
		for _, d := range u.DenyCidrs {
			// check if ip is in cidr
			_, cidr, err := net.ParseCIDR(d)
			if err != nil {
				l.WithError(err).Error("Failed to parse cidr")
				return false
			}
			if cidr.Contains(net.ParseIP(ip)) {
				l.Debug("IP is denied")
				return false
			}
		}
		l.Debug("IP is not denied")
		return true
	}
	l.Debug("IP is allowed")
	return true
}

func GetUpstreams() map[string]*Upstream {
	var us map[string]*Upstream
	err := memory.Get("upstreams", &us)
	if err != nil {
		log.WithError(err).Debug("Failed to get upstreams from memory")
		return nil
	}
	return us
}

func GetUpstreamForHost(host string) (*Upstream, error) {
	l := log.WithFields(log.Fields{
		"fn":   "GetUpstreamForHost",
		"host": host,
	})
	l.Debug("Getting upstream for host")
	if upstream, ok := GetUpstreams()[host]; ok {
		l.Debug("Found upstream for host")
		return upstream, nil
	}
	return nil, fmt.Errorf("no upstream found for host: %s", host)
}

func (r *UpstreamRegistrationRequest) Register() error {
	l := log.WithFields(log.Fields{
		"fn": "Register",
	})
	l.Debug("Registering upstream")
	if err := r.Upstream.Validate(); err != nil {
		l.WithError(err).Error("Failed to validate upstream")
		return err
	}
	if RegistrationKey != "" && r.RegistrationKey != RegistrationKey {
		return fmt.Errorf("registration key does not match")
	}
	l.WithFields(log.Fields{
		"ext":       r.Upstream.ExternalHost,
		"int":       r.Upstream.InternalHost,
		"port":      r.Upstream.Port,
		"timeout":   r.Upstream.Timeout,
		"rateLimit": r.Upstream.RateLimit,
	}).Debug("Registering upstream")
	if err := r.Upstream.TestConnection(); err != nil {
		l.WithError(err).Error("Failed to test connection")
		return err
	}
	// check that the public keys match
	us := GetUpstreams()
	if exist, ok := us[r.Upstream.ExternalHost]; ok {
		if string(exist.AdminCert) != string(r.Upstream.AdminCert) {
			return fmt.Errorf("upstream cert does not match")
		}
		l.Debug("Upstream already registered, updating")
	}
	if us == nil {
		us = make(map[string]*Upstream)
	}
	us[r.Upstream.ExternalHost] = r.Upstream
	if err := memory.Set("upstreams", us); err != nil {
		l.WithError(err).Error("Failed to set upstreams in memory")
		return err
	}
	return nil
}

func (r *UpstreamRegistrationRequest) Deregister() error {
	l := log.WithFields(log.Fields{
		"fn": "Deregister",
	})
	l.Debug("Deregistering upstream")
	if err := r.Upstream.Validate(); err != nil {
		l.WithError(err).Error("Failed to validate upstream")
		return err
	}
	if RegistrationKey != "" && r.RegistrationKey != RegistrationKey {
		return fmt.Errorf("registration key does not match")
	}
	// check that the public keys match
	us := GetUpstreams()
	if exist, ok := us[r.Upstream.ExternalHost]; ok {
		if string(exist.AdminCert) != string(r.Upstream.AdminCert) {
			return fmt.Errorf("upstream cert does not match")
		}
	}
	if _, ok := us[r.Upstream.ExternalHost]; !ok {
		return fmt.Errorf("upstream not registered: %s", r.Upstream.ExternalHost)
	}
	delete(us, r.Upstream.ExternalHost)
	if err := memory.Set("upstreams", us); err != nil {
		l.WithError(err).Error("Failed to set upstreams in memory")
		return err
	}
	return nil
}

func (u *Upstream) GenerateRegistrationRequest(key *rsa.PrivateKey) (*UpstreamRegistrationRequest, error) {
	l := log.WithFields(log.Fields{
		"fn": "GenerateRegistrationRequest",
	})
	l.Debug("Generating registration request")
	u.RequestTime = time.Now()
	if err := u.Validate(); err != nil {
		l.WithError(err).Error("Failed to validate upstream")
		return nil, err
	}
	publicKeyPem, err := keys.PrivateKeyToPublicPem(key)
	if err != nil {
		l.WithError(err).Error("Failed to get public key pem")
		return nil, err
	}
	u.AdminCert = publicKeyPem
	jd, err := json.Marshal(u)
	if err != nil {
		l.WithError(err).Error("Failed to marshal upstream")
		return nil, err
	}
	sig, err := keys.Sign(jd, key)
	if err != nil {
		l.WithError(err).Error("Failed to sign upstream")
		return nil, err
	}
	return &UpstreamRegistrationRequest{
		Payload:   jd,
		Signature: sig,
	}, nil
}

func sendDataTCP(data []byte, gc *GateServerConfig) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"fn":     "sendDataTCP",
		"server": gc.Server,
	})
	l.Debug("Sending data over tcp")
	// connect to gate using tcp / tls
	var conn net.Conn
	var err error
	var useTls bool
	tlsConfig := &tls.Config{}
	if gc.TLS.CA != "" {
		caCert, err := os.ReadFile(gc.TLS.CA)
		if err != nil {
			l.WithError(err).Error("Failed to read ca cert")
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
		useTls = true
	}
	if gc.TLS.Cert != "" && gc.TLS.Key != "" {
		cert, err := tls.LoadX509KeyPair(gc.TLS.Cert, gc.TLS.Key)
		if err != nil {
			l.WithError(err).Error("Failed to load cert")
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		useTls = true
	}
	if gc.TLS.Insecure {
		l.Debug("Skipping TLS verification")
		tlsConfig.InsecureSkipVerify = true
		useTls = true
	}
	l.Debug("Dialing server")
	if !useTls {
		conn, err = net.Dial("tcp", gc.Server)
		if err != nil {
			l.WithError(err).Error("Failed to dial server")
			return nil, err
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d := tls.Dialer{
			Config: tlsConfig,
		}
		conn, err = d.DialContext(ctx, "tcp", gc.Server)
		if err != nil {
			l.WithError(err).Error("Failed to dial server")
			return nil, err
		}
		l.Debug("Connected to server")
	}
	// send data
	l.Debug("Writing data")
	if _, err := conn.Write(data); err != nil {
		l.WithError(err).Error("Failed to write data")
		return nil, err
	}
	l.Debug("Closing write")
	// indicate to server that we are done sending data
	if useTls {
		if err := conn.(*tls.Conn).CloseWrite(); err != nil {
			l.WithError(err).Error("Failed to close write")
			return nil, err
		}
	} else {
		// close tcp write
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			l.WithError(err).Error("Failed to close write")
			return nil, err
		}
	}
	l.Debug("Reading response")
	// read response until EOF
	buf := make([]byte, 0)
	for {
		tmp := make([]byte, 1024)
		n, err := conn.Read(tmp)
		if err != nil {
			l.WithError(err).Error("Failed to read response")
			return nil, err
		}
		buf = append(buf, tmp[:n]...)
		if n < 1024 {
			break
		}
	}
	// close connection
	if err := conn.Close(); err != nil {
		l.WithError(err).Error("Failed to close connection")
		return nil, err
	}
	return buf, nil
}

func (u *Upstream) RegisterWithGate(key *rsa.PrivateKey, gc *GateServerConfig) error {
	l := log.WithFields(log.Fields{
		"fn":     "RegisterWithGate",
		"server": gc.Server,
	})
	l.Debug("Registering with gate")
	req, err := u.GenerateRegistrationRequest(key)
	if err != nil {
		l.WithError(err).Error("Failed to generate registration request")
		return err
	}
	req.Type = RegisterTypeRegister
	req.RegistrationKey = gc.RegistrationKey
	jd, err := json.Marshal(req)
	if err != nil {
		l.WithError(err).Error("Failed to marshal registration request")
		return err
	}
	// connect to gate and send request over tcp
	l.Debug("Sending registration request", string(jd))
	resp, err := sendDataTCP(jd, gc)
	if err != nil {
		l.WithError(err).Error("Failed to send registration request")
		return err
	}
	var response UpstreamRegistrationResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		l.WithError(err).Error("Failed to unmarshal response")
		return err
	}
	if !response.Success {
		l.WithError(err).Error("Failed to register upstream")
		return fmt.Errorf("failed to register upstream: %s", response.Message)
	} else {
		l.Debug("Successfully registered upstream")
	}
	return nil
}

func (u *Upstream) DeregisterWithGate(key *rsa.PrivateKey, gc *GateServerConfig) error {
	l := log.WithFields(log.Fields{
		"fn":     "DeregisterWithGate",
		"server": gc.Server,
	})
	l.Debug("Deregistering with gate")
	req, err := u.GenerateRegistrationRequest(key)
	if err != nil {
		l.WithError(err).Error("Failed to generate registration request")
		return err
	}
	req.Type = RegisterTypeDeregister
	req.RegistrationKey = gc.RegistrationKey
	jd, err := json.Marshal(req)
	if err != nil {
		l.WithError(err).Error("Failed to marshal registration request")
		return err
	}
	l.Debug("Sending registration request", string(jd))
	resp, err := sendDataTCP(jd, gc)
	if err != nil {
		l.WithError(err).Error("Failed to send registration request")
		return err
	}
	var response UpstreamRegistrationResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		l.WithError(err).Error("Failed to unmarshal response")
		return err
	}
	if !response.Success {
		l.WithError(err).Error("Failed to deregister upstream")
		return fmt.Errorf("failed to deregister upstream: %s", response.Message)
	} else {
		l.Debug("Successfully deregistered upstream")
	}
	return nil
}
