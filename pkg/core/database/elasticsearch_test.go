package database

import (
	"crypto/tls"
	"testing"
)

func TestBuildESTransportForHTTP(t *testing.T) {
	transport, err := buildESTransport("http://127.0.0.1:9200")
	if err != nil {
		t.Fatalf("buildESTransport returned error: %v", err)
	}
	if transport.TLSClientConfig != nil {
		t.Fatal("HTTP ES transport should not configure TLS")
	}
}

func TestBuildESTransportForHTTPSValidatesCertificates(t *testing.T) {
	transport, err := buildESTransport("https://es.example.com:9200")
	if err != nil {
		t.Fatalf("buildESTransport returned error: %v", err)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("HTTPS ES transport should configure TLS")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("HTTPS ES transport must validate certificates")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("HTTPS ES transport TLS minimum = %v, want TLS 1.2", transport.TLSClientConfig.MinVersion)
	}
}

func TestBuildESTransportRejectsUnsupportedScheme(t *testing.T) {
	if _, err := buildESTransport("es://127.0.0.1:9200"); err == nil {
		t.Fatal("expected unsupported ES address scheme to be rejected")
	}
}
