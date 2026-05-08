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
	domain, err := client.getDomainByName(zoneToApex(zone))
	if err != nil {
		return nil, err
	}
	return client.getRecords(ctx, domain)
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIToken, p.APISecret)
	apex := zoneToApex(zone)
	domain, err := client.getDomainByName(apex)
	if err != nil {
		return nil, err
	}
	return client.createRecords(ctx, domain, apex, records)
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIToken, p.APISecret)
	apex := zoneToApex(zone)
	domain, err := client.getDomainByName(apex)
	if err != nil {
		return nil, err
	}
	return client.deleteRecords(ctx, domain, apex, records)
}

// zoneToApex extracts the registrable apex domain from a zone string.
// Caddy may pass "_acme-challenge.status.ybmn.no." or "ybmn.no." —
// we always want "ybmn.no" to match the domeneshop API.
func zoneToApex(zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	parts := strings.Split(zone, ".")
	if len(parts) < 2 {
		return zone
	}
	// Return last two labels: "ybmn.no"
	return strings.Join(parts[len(parts)-2:], ".")
}

// Ensure interfaces are satisfied
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
