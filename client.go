// client.go
package domeneshop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/libdns/libdns"
	"net/http"
)

const baseURL = "https://api.domeneshop.no/v0"

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
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, buf)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.token, c.secret)
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
}

func (c *client) getDomainByName(name string) (*domain, error) {
	resp, err := c.do(context.Background(), "GET", "/domains", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var domains []domain
	json.NewDecoder(resp.Body).Decode(&domains)
	for _, d := range domains {
		if d.Name == name {
			return &d, nil
		}
	}
	return nil, fmt.Errorf("domain %q not found", name)
}

func (c *client) getRecords(ctx context.Context, d *domain) ([]libdns.Record, error) {
	resp, err := c.do(ctx, "GET", fmt.Sprintf("/domains/%d/dns", d.ID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var records []dnsRecord
	json.NewDecoder(resp.Body).Decode(&records)
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

func (c *client) createRecords(ctx context.Context, d *domain, records []libdns.Record) ([]libdns.Record, error) {
	created := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		r := record.RR()
		body := dnsRecord{Host: r.Name, Type: r.Type, Data: r.Data, TTL: 300}
		resp, err := c.do(ctx, "POST", fmt.Sprintf("/domains/%d/dns", d.ID), body)
		if err != nil {
			return created, err
		}
		resp.Body.Close()
		created = append(created, r)
	}
	return created, nil
}

func (c *client) deleteRecords(ctx context.Context, d *domain, records []libdns.Record) ([]libdns.Record, error) {
	// Fetch all records to find IDs matching what we want to delete
	all, err := c.getRecords(ctx, d)
	if err != nil {
		return nil, err
	}
	// Build a map of existing records with their IDs
	resp, _ := c.do(ctx, "GET", fmt.Sprintf("/domains/%d/dns", d.ID), nil)
	var raw []dnsRecord
	json.NewDecoder(resp.Body).Decode(&raw)
	resp.Body.Close()

	deleted := make([]libdns.Record, 0)
	for _, record := range records {
		r := record.RR()
		for _, existing := range raw {
			if existing.Host == r.Name && existing.Type == r.Type && existing.Data == r.Data {
				delResp, err := c.do(ctx, "DELETE",
					fmt.Sprintf("/domains/%d/dns/%d", d.ID, existing.ID), nil)
				if err == nil {
					delResp.Body.Close()
					deleted = append(deleted, r)
				}
			}
		}
	}
	_ = all
	return deleted, nil
}
