// provider.go
package domeneshop

import (
	"context"
	"fmt"
	"strings"

	"github.com/libdns/libdns"
)

// Provider implements the libdns interfaces for Domeneshop.
//
// We deliberately do NOT trust the `zone` argument that certmagic/libdns
// passes in. Some resolvers and certmagic's zone-finder can settle on a
// public-suffix-ish zone like "no." for *.ybmn.no, which would then make
// us ask the API for a domain we don't own. Instead, we list the
// account's domains and pick the longest suffix match against the
// record's FQDN — that's the registrable apex we should operate on.
type Provider struct {
	APIToken  string `json:"api_token"`
	APISecret string `json:"api_secret"`
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	client := newClient(p.APIToken, p.APISecret)
	domains, err := client.listDomains(ctx)
	if err != nil {
		return nil, err
	}
	d, _ := pickDomainForName(domains, zone)
	if d == nil {
		// Fall back to the legacy zone-trim path for GetRecords callers that
		// pass a clean apex zone — keeps backwards compat for non-ACME use.
		d, _ = pickDomainForName(domains, zoneToApex(zone))
	}
	if d == nil {
		return nil, fmt.Errorf("no domeneshop-managed domain matches zone %q", zone)
	}
	return client.getRecords(ctx, d)
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIToken, p.APISecret)
	domains, err := client.listDomains(ctx)
	if err != nil {
		return nil, err
	}

	created := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		r := rec.RR()
		d, apex := pickDomainForName(domains, r.Name)
		if d == nil {
			return created, fmt.Errorf("no domeneshop-managed domain matches %q", r.Name)
		}
		out, err := client.createRecord(ctx, d, apex, r)
		if err != nil {
			return created, err
		}
		created = append(created, out)
	}
	return created, nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIToken, p.APISecret)
	domains, err := client.listDomains(ctx)
	if err != nil {
		return nil, err
	}

	deleted := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		r := rec.RR()
		d, apex := pickDomainForName(domains, r.Name)
		if d == nil {
			return deleted, fmt.Errorf("no domeneshop-managed domain matches %q", r.Name)
		}
		out, err := client.deleteRecord(ctx, d, apex, r)
		if err != nil {
			return deleted, err
		}
		if out != nil {
			deleted = append(deleted, *out)
		}
	}
	return deleted, nil
}

// pickDomainForName picks the registered domain whose name is the longest
// suffix of name, plus the apex string to pass to libdns.RelativeName.
// Match is case-insensitive and tolerates a trailing dot.
func pickDomainForName(domains []domain, name string) (*domain, string) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	var best *domain
	for i, d := range domains {
		dn := strings.ToLower(d.Name)
		if n == dn || strings.HasSuffix(n, "."+dn) {
			if best == nil || len(dn) > len(best.Name) {
				best = &domains[i]
			}
		}
	}
	if best == nil {
		return nil, ""
	}
	return best, best.Name
}

// zoneToApex extracts the registrable apex domain from a zone string.
// Kept for backwards compat with callers passing a pre-trimmed zone.
// New code path uses pickDomainForName against the API-returned domain list.
func zoneToApex(zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	parts := strings.Split(zone, ".")
	if len(parts) < 2 {
		return zone
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// Ensure interfaces are satisfied
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
