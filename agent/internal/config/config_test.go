package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("파일 작성: %v", err)
	}
	return path
}

// selfSignedCAPEM 은 고정 검증용 CA 인증서를 만든다.
func selfSignedCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("키 생성: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "edrdog-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("인증서 생성: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestLoadAppliesDefaults(t *testing.T) {
	path := write(t, "config.json", `{"base_url":"https://edr.example","enroll_secret":"s"}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.HostIdentifier == "" {
		t.Error("HostIdentifier 가 비었다. 비면 호스트 이름으로 채워야 한다")
	}
	if cfg.FlushIntervalSeconds != 5 {
		t.Errorf("FlushIntervalSeconds = %d, want 5", cfg.FlushIntervalSeconds)
	}
	if cfg.BufferSize != 10000 {
		t.Errorf("BufferSize = %d, want 10000", cfg.BufferSize)
	}
	if cfg.BatchSize != 500 {
		t.Errorf("BatchSize = %d, want 500", cfg.BatchSize)
	}
}

func TestLoadKeepsExplicitValues(t *testing.T) {
	path := write(t, "config.json", `{
		"base_url":"https://edr.example",
		"enroll_secret":"s",
		"host_identifier":"lab-mac",
		"flush_interval_seconds":30,
		"buffer_size":100,
		"batch_size":10
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HostIdentifier != "lab-mac" {
		t.Errorf("HostIdentifier = %q, want lab-mac", cfg.HostIdentifier)
	}
	if cfg.FlushIntervalSeconds != 30 || cfg.BufferSize != 100 || cfg.BatchSize != 10 {
		t.Errorf("명시값이 기본값에 덮였다: %+v", cfg)
	}
}

func TestLoadRejectsMissingRequiredFields(t *testing.T) {
	cases := map[string]string{
		"base_url 없음":      `{"enroll_secret":"s"}`,
		"enroll_secret 없음": `{"base_url":"https://edr.example"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, "config.json", body)); err == nil {
				t.Fatal("필수값이 없는데 err 가 nil 이다")
			}
		})
	}
}

func TestLoadStripsTrailingSlashFromBaseURL(t *testing.T) {
	// 경로를 이어 붙이므로 슬래시가 겹치면 서버가 404 를 낸다.
	path := write(t, "config.json", `{"base_url":"https://edr.example/","enroll_secret":"s"}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != "https://edr.example" {
		t.Errorf("BaseURL = %q, want https://edr.example", cfg.BaseURL)
	}
}

func TestLoadFailsOnMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "none.json")); err == nil {
		t.Fatal("없는 파일인데 err 가 nil 이다")
	}
}

func TestHTTPClientTrustsOnlyPinnedCA(t *testing.T) {
	// 인증서를 지정하면 그 CA 만 신뢰해야 한다. 시스템 신뢰 저장소를 같이 쓰면 고정이 아니다.
	cfg := Config{
		BaseURL:      "https://edr.example",
		EnrollSecret: "s",
		CACertPath:   write(t, "ca.pem", selfSignedCAPEM(t)),
	}

	client, err := cfg.HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport 타입 = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("RootCAs 가 비었다. 고정이 걸리지 않았다")
	}
}

func TestHTTPClientWithoutCAUsesSystemTrust(t *testing.T) {
	cfg := Config{BaseURL: "https://edr.example", EnrollSecret: "s"}

	client, err := cfg.HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient: %v", err)
	}
	if client.Timeout <= 0 {
		t.Error("Timeout 이 없다. 서버가 응답을 안 하면 전송이 영영 막힌다")
	}
}

func TestHTTPClientRejectsBadCA(t *testing.T) {
	cfg := Config{
		BaseURL:      "https://edr.example",
		EnrollSecret: "s",
		CACertPath:   write(t, "ca.pem", "인증서가 아님"),
	}

	if _, err := cfg.HTTPClient(); err == nil {
		t.Fatal("깨진 CA 인데 err 가 nil 이다")
	}
}
