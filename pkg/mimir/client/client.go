// SPDX-License-Identifier: AGPL-3.0-only
// Provenance-includes-location: https://github.com/grafana/cortex-tools/blob/main/pkg/client/client.go
// Provenance-includes-license: Apache-2.0
// Provenance-includes-copyright: The Cortex Authors.

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	weaveworksClient "github.com/weaveworks/common/http/client"
	"github.com/weaveworks/common/instrument"
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
	ID               string
	Address          string
	UseLegacyRoutes  bool
	HTTPClientConfig config.HTTPClientConfig
}

type Interface interface {
	CreateRuleGroup(ctx context.Context, namespace string, rg RuleGroup) error
	DeleteRuleGroup(ctx context.Context, namespace, groupName string) error
	ListRules(ctx context.Context, namespace string) (map[string][]RuleGroup, error)
}

// MimirClient is a client to the Mimir API.
type MimirClient struct {
	id string

	endpoint *url.URL
	client   weaveworksClient.Requester
	apiPath  string
	logger   log.Logger
}

// New returns a new MimirClient.
func New(logger log.Logger, cfg Config, timingHistogram *prometheus.HistogramVec) (*MimirClient, error) {
	endpoint, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, err
	}
	client, err := config.NewClientFromConfig(cfg.HTTPClientConfig, "GrafanaAgent", config.WithHTTP2Disabled())
	if err != nil {
		return nil, err
	}

	path := rulerAPIPath
	if cfg.UseLegacyRoutes {
		path = legacyAPIPath
	}

	collector := instrument.NewHistogramCollector(timingHistogram)
	timedClient := weaveworksClient.NewTimedClient(client, collector)

	return &MimirClient{
		id:       cfg.ID,
		endpoint: endpoint,
		client:   timedClient,
		apiPath:  path,
		logger:   logger,
	}, nil
}

func (r *MimirClient) doRequest(operation, path, method string, payload io.Reader, contentLength int64) (*http.Response, error) {
	req, err := buildRequest(operation, path, method, *r.endpoint, payload, contentLength)
	if err != nil {
		return nil, err
	}

	if r.id != "" {
		req.Header.Add(user.OrgIDHeaderName, r.id)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}

	if err := checkResponse(resp); err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("error %s %s: %w", method, path, err)
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
		return fmt.Errorf("error reading response body: %w", err)
	}
	bodyStr := string(bodyHead)
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

func buildRequest(op, p, m string, endpoint url.URL, payload io.Reader, contentLength int64) (*http.Request, error) {
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

	r = r.WithContext(context.WithValue(r.Context(), weaveworksClient.OperationNameContextKey, op))

	return r, nil
}
