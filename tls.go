package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

var ErrInvalidClientCA = errors.New("failed to parse client CA certificate")

type tlsConfig struct {
	ServerKey  string `and:"tls-server,mtls" help:"TLS key for server"`
	ServerCert string `and:"tls-server,mtls" help:"TLS certificate (chain) for server"`

	ClientCA        []string `type:"existingfile" and:"mtls" help:"Client CA cert for client verification"`
	EnforceClientCA bool     `and:"mtls" help:"Require that the client provide a valid certificate"`

	ListenTLS bool `and:"tls-server" help:"Only accept TLS connections. If false, STARTTLS can be used."`

	tlsConfig *tls.Config
}

func (t *tlsConfig) AfterApply() error {
	if t.ServerCert == "" {
		// No TLS configured
		return nil
	}
	c, err := tls.LoadX509KeyPair(t.ServerCert, t.ServerKey)
	if err != nil {
		return err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{c},
	}
	for _, clientCA := range t.ClientCA {
		if cfg.ClientCAs == nil {
			cfg.ClientCAs = x509.NewCertPool()
			if t.EnforceClientCA {
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
			} else {
				cfg.ClientAuth = tls.VerifyClientCertIfGiven
			}
		}
		cert, err := os.ReadFile(clientCA)
		if err != nil {
			return err
		}
		if cfg.ClientCAs.AppendCertsFromPEM(cert) {
			return fmt.Errorf("%w: %s", ErrInvalidClientCA, clientCA)
		}
	}

	t.tlsConfig = cfg
	return nil
}

func (t *tlsConfig) AsTLSConfig() *tls.Config {
	return t.tlsConfig
}
