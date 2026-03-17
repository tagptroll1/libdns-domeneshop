// provider.go
package domeneshop

import (
	"context"
	"strings"

	"github.com/libdns/libdns"
)

// Provider implements the libdns interfaces for Domeneshop
type Provider struct {
	APIToken  string `json:"api_token"`
	APISecret string `json:"api_secret"`
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	client := newClient(p.APIToken, p.APISecret)
	domain, err := client.getDomainByName(trimZone(zone))
	if err != nil {
		return nil, err
	}
	return client.getRecords(ctx, domain)
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIToken, p.APISecret)
	domain, err := client.getDomainByName(trimZone(zone))
	if err != nil {
		return nil, err
	}
	return client.createRecords(ctx, domain, records)
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIToken, p.APISecret)
	domain, err := client.getDomainByName(trimZone(zone))
	if err != nil {
		return nil, err
	}
	return client.deleteRecords(ctx, domain, records)
}

// libdns zones are dot-terminated, domeneshop wants bare domain names
func trimZone(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

// Ensure interfaces are satisfied
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
