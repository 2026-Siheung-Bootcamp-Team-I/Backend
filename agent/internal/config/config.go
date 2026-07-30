// Package config 는 에이전트 설정 파일을 읽는다.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config 는 설정 파일의 내용이다.
type Config struct {
	BaseURL      string `json:"base_url"`
	EnrollSecret string `json:"enroll_secret"`
	// HostIdentifier 는 서버에서 기기를 가리키는 이름이다. 비우면 호스트 이름을 쓴다.
	HostIdentifier string `json:"host_identifier"`
	// CACertPath 를 지정하면 그 CA 로 서명한 서버만 신뢰한다(osquery 의 인증서 고정과 같은 목적).
	// 비우면 시스템 신뢰 저장소를 쓴다.
	CACertPath           string `json:"ca_cert_path"`
	FlushIntervalSeconds int    `json:"flush_interval_seconds"`
	BufferSize           int    `json:"buffer_size"`
	BatchSize            int    `json:"batch_size"`
}

// Load 는 설정 파일을 읽고 기본값을 채운 뒤 검증한다.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("설정 파일을 읽을 수 없다(%s): %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("설정 파일이 올바른 JSON 이 아니다(%s): %w", path, err)
	}
	if err := cfg.applyDefaults(); err != nil {
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() error {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if c.HostIdentifier == "" {
		name, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("host_identifier 가 비었는데 호스트 이름도 못 읽었다: %w", err)
		}
		c.HostIdentifier = name
	}
	if c.FlushIntervalSeconds <= 0 {
		c.FlushIntervalSeconds = 5
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 10000
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 500
	}
	return nil
}

func (c Config) validate() error {
	if c.BaseURL == "" {
		return errors.New("base_url 이 필요하다")
	}
	if c.EnrollSecret == "" {
		return errors.New("enroll_secret 이 필요하다")
	}
	return nil
}

// FlushInterval 은 전송 주기다.
func (c Config) FlushInterval() time.Duration {
	return time.Duration(c.FlushIntervalSeconds) * time.Second
}

// HTTPClient 는 설정에 맞춘 HTTP 클라이언트를 만든다.
// CACertPath 가 있으면 그 CA 하나만 신뢰한다. 시스템 저장소를 같이 쓰면 고정이 아니게 된다.
func (c Config) HTTPClient() (*http.Client, error) {
	timeout := c.FlushInterval()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	if c.CACertPath == "" {
		return client, nil
	}

	pem, err := os.ReadFile(c.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("CA 인증서를 읽을 수 없다(%s): %w", c.CACertPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA 인증서에서 유효한 인증서를 찾지 못했다(%s)", c.CACertPath)
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return client, nil
}
