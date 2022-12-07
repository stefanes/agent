// SPDX-License-Identifier: AGPL-3.0-only
// Provenance-includes-location: https://github.com/grafana/cortex-tools/blob/main/pkg/client/client.go
// Provenance-includes-license: Apache-2.0
// Provenance-includes-copyright: The Cortex Authors.

package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/go-kit/log"
	"github.com/grafana/dskit/crypto/tls"
	"github.com/pkg/errors"
	"github.com/prometheus/statsd_exporter/pkg/level"
	"github.com/weaveworks/common/user"
)

const (
	rulerAPIPath  = "/prometheus/config/v1/rules"
	legacyAPIPath = "/api/v1/rules"
)

var (
	ErrResourceNotFound = errors.New("requested resource not found")
	errConflict         = errors.New("conflict with current state of target resource")
)

// Config is used to configure a MimirClient.
type Config struct {
	User            string `yaml:"user"`
	Key             string `yaml:"key"`
	Address         string `yaml:"address"`
	ID              string `yaml:"id"`
	TLS             tls.ClientConfig
	UseLegacyRoutes bool   `yaml:"use_legacy_routes"`
	AuthToken       string `yaml:"auth_token"`
}

type Interface interface {
	CreateRuleGroup(ctx context.Context, namespace string, rg RuleGroup) error
	DeleteRuleGroup(ctx context.Context, namespace, groupName string) error
	ListRules(ctx context.Context, namespace string) (map[string][]RuleGroup, error)
}

// MimirClient is a client to the Mimir API.
type MimirClient struct {
	user      string
	key       string
	id        string
	endpoint  *url.URL
	Client    http.Client
	apiPath   string
	authToken string
	logger    log.Logger
}

// New returns a new MimirClient.
func New(logger log.Logger, cfg Config) (*MimirClient, error) {
	endpoint, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, err
	}

	level.Debug(logger).Log("msg", "New Mimir client created", "address", cfg.Address, "id", cfg.ID)

	client := http.Client{}

	// Setup TLS client
	tlsConfig, err := cfg.TLS.GetTLSConfig()
	if err != nil {
		level.Error(logger).Log(
			"msg", "error loading TLS files",
			"tls-ca", cfg.TLS.CAPath,
			"tls-cert", cfg.TLS.CertPath,
			"tls-key", cfg.TLS.KeyPath,
			"err", err,
		)
		return nil, fmt.Errorf("Mimir client initialization unsuccessful")
	}

	if tlsConfig != nil {
		transport := &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: tlsConfig,
		}
		client = http.Client{Transport: transport}
	}

	path := rulerAPIPath
	if cfg.UseLegacyRoutes {
		path = legacyAPIPath
	}

	return &MimirClient{
		user:      cfg.User,
		key:       cfg.Key,
		id:        cfg.ID,
		endpoint:  endpoint,
		Client:    client,
		apiPath:   path,
		authToken: cfg.AuthToken,
		logger:    logger,
	}, nil
}

func (r *MimirClient) doRequest(path, method string, payload io.Reader, contentLength int64) (*http.Response, error) {
	req, err := buildRequest(path, method, *r.endpoint, payload, contentLength)
	if err != nil {
		return nil, err
	}

	switch {
	case (r.user != "" || r.key != "") && r.authToken != "":
		return nil, errors.New("at most one of basic auth or auth token should be configured")

	case r.user != "":
		req.SetBasicAuth(r.user, r.key)

	case r.key != "":
		req.SetBasicAuth(r.id, r.key)

	case r.authToken != "":
		req.Header.Add("Authorization", "Bearer "+r.authToken)
	}

	req.Header.Add(user.OrgIDHeaderName, r.id)

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if err := checkResponse(resp); err != nil {
		_ = resp.Body.Close()
		return nil, errors.Wrapf(err, "%s request to %s failed", req.Method, req.URL.String())
	}

	return resp, nil
}

// checkResponse checks an API response for errors.
func checkResponse(r *http.Response) error {
	if 200 <= r.StatusCode && r.StatusCode <= 299 {
		return nil
	}

	bodyHead, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		return errors.Wrapf(err, "reading body")
	}
	bodyStr := string(bodyHead)
	const msg = "response"
	if r.StatusCode == http.StatusNotFound {
		return ErrResourceNotFound
	}
	if r.StatusCode == http.StatusConflict {
		return errConflict
	}

	var errMsg string
	if bodyStr == "" {
		errMsg = fmt.Sprintf("server returned HTTP status: %s", r.Status)
	} else {
		errMsg = fmt.Sprintf("server returned HTTP status: %s, body: %q", r.Status, bodyStr)
	}

	return errors.New(errMsg)
}

func joinPath(baseURLPath, targetPath string) string {
	// trim exactly one slash at the end of the base URL, this expects target
	// path to always start with a slash
	return strings.TrimSuffix(baseURLPath, "/") + targetPath
}

func buildRequest(p, m string, endpoint url.URL, payload io.Reader, contentLength int64) (*http.Request, error) {
	// parse path parameter again (as it already contains escaped path information
	pURL, err := url.Parse(p)
	if err != nil {
		return nil, err
	}

	// if path or endpoint contains escaping that requires RawPath to be populated, also join rawPath
	if pURL.RawPath != "" || endpoint.RawPath != "" {
		endpoint.RawPath = joinPath(endpoint.EscapedPath(), pURL.EscapedPath())
	}
	endpoint.Path = joinPath(endpoint.Path, pURL.Path)
	endpoint.RawQuery = pURL.RawQuery
	r, err := http.NewRequest(m, endpoint.String(), payload)
	if err != nil {
		return nil, err
	}
	if contentLength >= 0 {
		r.ContentLength = contentLength
	}
	return r, nil
}
