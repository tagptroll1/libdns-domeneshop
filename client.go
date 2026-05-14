// client.go
package domeneshop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/libdns/libdns"
)

// baseURLVar is the API root. It's a var (not const) so tests can swap
// it for an httptest server URL. Not part of the public surface.
var baseURLVar = "https://api.domeneshop.no/v0"

type client struct {
	token  string
	secret string
	http   *http.Client
}

func newClient(token, secret string) *client {
	return &client{token: token, secret: secret, http: &http.Client{}}
}

type domain struct {
	ID   int    `json:"id"`
	Name string `json:"domain"`
}

type dnsRecord struct {
	ID   int    `json:"id,omitempty"`
	Host string `json:"host"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

func (c *client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = &bytes.Buffer{}
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURLVar+path, buf)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.token, c.secret)
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
}

func (c *client) listDomains(ctx context.Context) ([]domain, error) {
	resp, err := c.do(ctx, "GET", "/domains", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("domeneshop list domains: %s: %s", resp.Status, bytes.TrimSpace(b))
	}
	var domains []domain
	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		return nil, fmt.Errorf("domeneshop list domains: %w", err)
	}
	return domains, nil
}

func (c *client) getRecords(ctx context.Context, d *domain) ([]libdns.Record, error) {
	resp, err := c.do(ctx, "GET", fmt.Sprintf("/domains/%d/dns", d.ID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var records []dnsRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, fmt.Errorf("domeneshop list records: %w", err)
	}
	out := make([]libdns.Record, 0, len(records))
	for _, r := range records {
		out = append(out, libdns.RR{
			Type: r.Type,
			Name: r.Host,
			Data: r.Data,
		})
	}
	return out, nil
}

func (c *client) createRecord(ctx context.Context, d *domain, zone string, r libdns.RR) (libdns.Record, error) {
	body := dnsRecord{
		Host: libdns.RelativeName(strings.TrimSuffix(r.Name, "."), zone),
		Type: r.Type,
		Data: r.Data,
		TTL:  300,
	}
	resp, err := c.do(ctx, "POST", fmt.Sprintf("/domains/%d/dns", d.ID), body)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return r, fmt.Errorf("domeneshop create %s %q: %s: %s",
			r.Type, body.Host, resp.Status, bytes.TrimSpace(b))
	}
	return r, nil
}

func (c *client) deleteRecord(ctx context.Context, d *domain, zone string, r libdns.RR) (*libdns.RR, error) {
	resp, err := c.do(ctx, "GET", fmt.Sprintf("/domains/%d/dns", d.ID), nil)
	if err != nil {
		return nil, err
	}
	var raw []dnsRecord
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("domeneshop list dns: %w", err)
	}
	resp.Body.Close()

	host := libdns.RelativeName(strings.TrimSuffix(r.Name, "."), zone)
	for _, existing := range raw {
		if existing.Host == host && existing.Type == r.Type && existing.Data == r.Data {
			delResp, err := c.do(ctx, "DELETE",
				fmt.Sprintf("/domains/%d/dns/%d", d.ID, existing.ID), nil)
			if err != nil {
				return nil, err
			}
			if delResp.StatusCode >= 300 {
				b, _ := io.ReadAll(delResp.Body)
				delResp.Body.Close()
				return nil, fmt.Errorf("domeneshop delete %d: %s: %s",
					existing.ID, delResp.Status, bytes.TrimSpace(b))
			}
			delResp.Body.Close()
			return &r, nil
		}
	}
	// No matching record found — treat as no-op (idempotent delete).
	return nil, nil
}
