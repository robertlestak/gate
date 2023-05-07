package gate

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/robertlestak/gate/pkg/keys"
	log "github.com/sirupsen/logrus"
)

func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}
	return hello, io.MultiReader(peekedBytes, reader), nil
}

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()

	if hello == nil {
		return nil, err
	}

	return hello, nil
}

func handleConnection(clientConn net.Conn) {
	l := log.WithFields(log.Fields{
		"fn": "handleConnection",
	})
	l.Debug("Handling connection")
	defer clientConn.Close()

	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		l.WithError(err).Error("Failed to set read deadline")
		return
	}

	clientHello, clientReader, err := peekClientHello(clientConn)
	if err != nil {
		l.WithError(err).Error("Failed to peek client hello")
		return
	}

	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		l.WithError(err).Error("Failed to clear read deadline")
		return
	}
	us, err := GetUpstreamForHost(clientHello.ServerName)
	if err != nil {
		l.WithError(err).Debug("Failed to get upstream for host")
		return
	}
	if !us.IsAllowed(clientConn.RemoteAddr().(*net.TCPAddr).IP.String()) {
		l.WithError(err).Debug("connection not allowed")
		return
	}
	backendConn, err := net.DialTimeout("tcp", net.JoinHostPort(us.InternalHost, fmt.Sprintf("%d", us.Port)), us.Timeout)
	if err != nil {
		l.WithError(err).Debug("Failed to dial backend")
		return
	}
	defer backendConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(clientConn, backendConn)
		clientConn.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()
	go func() {
		io.Copy(backendConn, clientReader)
		backendConn.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()

	wg.Wait()
}

func handleAdminConnection(clientConn net.Conn) {
	l := log.WithFields(log.Fields{
		"fn": "handleAdminConnection",
	})
	l.Debug("Handling admin connection")
	defer clientConn.Close()
	// read request body
	var buf bytes.Buffer
	l.Debug("Reading request body")
	if _, err := io.Copy(&buf, clientConn); err != nil {
		l.WithError(err).Error("Failed to read request body")
		return
	}
	// unmarshal request
	l.Debug("Unmarshalling request")
	var req UpstreamRegistrationRequest
	if err := json.Unmarshal(buf.Bytes(), &req); err != nil {
		l.WithError(err).Error("Failed to unmarshal request")
		if err := json.NewEncoder(clientConn).Encode(&UpstreamRegistrationResponse{
			Success: false,
			Message: err.Error(),
		}); err != nil {
			l.WithError(err).Error("Failed to send response")
			return
		}
		return
	}
	var us *Upstream
	if err := json.Unmarshal([]byte(req.Payload), &us); err != nil {
		l.WithError(err).Error("Failed to unmarshal upstream")
		if err := json.NewEncoder(clientConn).Encode(&UpstreamRegistrationResponse{
			Success: false,
			Message: err.Error(),
		}); err != nil {
			l.WithError(err).Error("Failed to send response")
			return
		}
		return
	}
	req.Upstream = us
	if err := keys.Verify([]byte(req.Payload), []byte(req.Signature), req.Upstream.AdminCert); err != nil {
		l.WithError(err).Error("Failed to verify upstream")
		if err := json.NewEncoder(clientConn).Encode(&UpstreamRegistrationResponse{
			Success: false,
			Message: err.Error(),
		}); err != nil {
			l.WithError(err).Error("Failed to send response")
			return
		}
		return
	}
	// ensure that req.Upstream.RequestTime is within the past 5 minutes
	if time.Since(req.Upstream.RequestTime) > 5*time.Minute {
		l.Error("Request time is too old")
		if err := json.NewEncoder(clientConn).Encode(&UpstreamRegistrationResponse{
			Success: false,
			Message: "request time is too old",
		}); err != nil {
			l.WithError(err).Error("Failed to send response")
			return
		}
		return
	}
	// validate request
	l.Debug("Validating request")
	if err := req.Upstream.Validate(); err != nil {
		l.WithError(err).Error("Failed to validate request")
		if err := json.NewEncoder(clientConn).Encode(&UpstreamRegistrationResponse{
			Success: false,
			Message: err.Error(),
		}); err != nil {
			l.WithError(err).Error("Failed to send response")
			return
		}
		return
	}
	// handle request
	switch req.Type {
	case RegisterTypeRegister:
		l.Debug("Registering upstream")
		if err := req.Register(); err != nil {
			l.WithError(err).Error("Failed to register upstream")
			if err := json.NewEncoder(clientConn).Encode(&UpstreamRegistrationResponse{
				Success: false,
				Message: err.Error(),
			}); err != nil {
				l.WithError(err).Error("Failed to send response")
				return
			}
			return
		}
	case RegisterTypeDeregister:
		l.Debug("Deregistering upstream")
		if err := req.Deregister(); err != nil {
			l.WithError(err).Error("Failed to deregister upstream")
			if err := json.NewEncoder(clientConn).Encode(&UpstreamRegistrationResponse{
				Success: false,
				Message: err.Error(),
			}); err != nil {
				l.WithError(err).Error("Failed to send response")
				return
			}
			return
		}
	default:
		l.Error("Unknown registration type")
		if err := json.NewEncoder(clientConn).Encode(&UpstreamRegistrationResponse{
			Success: false,
			Message: "unknown registration type",
		}); err != nil {
			l.WithError(err).Error("Failed to send response")
			return
		}
		return
	}
	// send response
	l.Debug("Sending response")
	if err := json.NewEncoder(clientConn).Encode(&UpstreamRegistrationResponse{
		Success: true,
	}); err != nil {
		l.WithError(err).Error("Failed to send response")
		return
	}
}

func Start(port int) error {
	l := log.WithFields(log.Fields{
		"port": port,
		"fn":   "Start",
	})
	l.Infof("Starting gate on :%d", port)
	// create tcp listener
	c, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		l.WithError(err).Error("Failed to create listener")
		return err
	}
	// accept connections
	for {
		conn, err := c.Accept()
		if err != nil {
			l.WithError(err).Error("Failed to accept connection")
			continue
		}
		go handleConnection(conn)
	}
}

func StartAdminServer(port int, cacert string, cert string, key string, clientAuth bool) error {
	l := log.WithFields(log.Fields{
		"port": port,
		"fn":   "StartAdminServer",
	})
	l.Infof("Starting gate admin on :%d", port)
	var useTls bool
	tlsConfig := &tls.Config{}
	if clientAuth {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		useTls = true
	}
	if cacert != "" {
		caCert, err := os.ReadFile(cacert)
		if err != nil {
			l.WithError(err).Fatal("Failed to read TLS CA certificate")
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		useTls = true
	}
	if cert != "" && key != "" {
		cert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			l.WithError(err).Error("Failed to load cert")
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		useTls = true
	}
	var c net.Listener
	var err error
	if useTls {
		c, err = tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
	} else {
		c, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	}
	if err != nil {
		l.WithError(err).Error("Failed to create listener")
		return err
	}
	// accept connections
	for {
		conn, err := c.Accept()
		if err != nil {
			l.WithError(err).Error("Failed to accept connection")
			continue
		}
		go handleAdminConnection(conn)
	}
}

func StartTLSRedirect(port int) error {
	l := log.WithFields(log.Fields{
		"port": port,
		"fn":   "StartTLSRedirect",
	})
	l.Infof("Starting gate TLS redirect on :%d", port)
	// for all incoming connections, redirect to https
	http.ListenAndServe(fmt.Sprintf(":%d", port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("https://%s%s", r.Host, r.URL), http.StatusMovedPermanently)
	}))
	return nil
}
