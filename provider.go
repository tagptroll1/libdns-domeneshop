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
		fqdn, d, apex := resolveFQDN(domains, r.Name, zone)
		if d == nil {
			return created, fmt.Errorf("no domeneshop-managed domain matches %q (zone %q)", r.Name, zone)
		}
		// createRecord needs the FQDN so it can derive the apex-relative
		// Host for the Domeneshop API. But the returned libdns.Record must
		// keep r.Name as the caller passed it (relative to the input zone),
		// otherwise certmagic's propagation check will AbsoluteName(...)
		// it again and end up querying e.g. _acme-challenge.X.ybmn.no.ybmn.no.
		apiCall := r
		apiCall.Name = fqdn
		if _, err := client.createRecord(ctx, d, apex, apiCall); err != nil {
			return created, err
		}
		created = append(created, rec)
	}
	return created, nil
}

// SetRecords replaces records in the zone for each (name, type) RRset.
// For every input record, all existing records with the same relative
// host and type are deleted, then the desired records are created. This
// is what certmagic uses for DNS-01: it guarantees the TXT under
// _acme-challenge.<host> always reflects the *current* challenge value,
// even if a previous attempt left stale records behind.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIToken, p.APISecret)
	domains, err := client.listDomains(ctx)
	if err != nil {
		return nil, err
	}

	// Group inputs by (domain, relative-host, type) so we wipe each RRset
	// exactly once before writing the desired records into it.
	type rrkey struct {
		domainID int
		host     string
		rtype    string
	}
	// Each entry pairs the FQDN-form RR we pass to the API with the
	// original caller-supplied Record we hand back unchanged. Returning
	// the original preserves Name's relativity to the input zone — see
	// AppendRecords for why that matters for the propagation check.
	type pair struct {
		apiCall libdns.RR
		orig    libdns.Record
	}
	type bucket struct {
		d     *domain
		apex  string
		host  string
		rtype string
		pairs []pair
	}
	buckets := make(map[rrkey]*bucket)
	order := []rrkey{}

	for _, rec := range records {
		r := rec.RR()
		fqdn, d, apex := resolveFQDN(domains, r.Name, zone)
		if d == nil {
			return nil, fmt.Errorf("no domeneshop-managed domain matches %q (zone %q)", r.Name, zone)
		}
		host := libdns.RelativeName(strings.TrimSuffix(fqdn, "."), apex)
		k := rrkey{d.ID, host, r.Type}
		if _, ok := buckets[k]; !ok {
			buckets[k] = &bucket{d: d, apex: apex, host: host, rtype: r.Type}
			order = append(order, k)
		}
		apiCall := r
		apiCall.Name = fqdn
		buckets[k].pairs = append(buckets[k].pairs, pair{apiCall: apiCall, orig: rec})
	}

	out := make([]libdns.Record, 0, len(records))
	for _, k := range order {
		b := buckets[k]

		existing, err := client.listRaw(ctx, b.d)
		if err != nil {
			return out, err
		}
		for _, e := range existing {
			if e.Host == b.host && e.Type == b.rtype {
				if err := client.deleteByID(ctx, b.d, e.ID); err != nil {
					return out, err
				}
			}
		}

		for _, p := range b.pairs {
			if _, err := client.createRecord(ctx, b.d, b.apex, p.apiCall); err != nil {
				return out, err
			}
			out = append(out, p.orig)
		}
	}
	return out, nil
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
		fqdn, d, apex := resolveFQDN(domains, r.Name, zone)
		if d == nil {
			return deleted, fmt.Errorf("no domeneshop-managed domain matches %q (zone %q)", r.Name, zone)
		}
		apiCall := r
		apiCall.Name = fqdn
		out, err := client.deleteRecord(ctx, d, apex, apiCall)
		if err != nil {
			return deleted, err
		}
		if out != nil {
			deleted = append(deleted, rec)
		}
	}
	return deleted, nil
}

// candidateFQDNs returns FQDN candidates to try matching against the owned
// domain list. We don't trust the zone arg (it can be misleading like "no."),
// nor do we know whether libdns passed name as already-absolute or as
// relative-to-zone. So we try the as-is form first, then the joined form.
func candidateFQDNs(name, zone string) []string {
	name = strings.TrimSuffix(name, ".")
	z := strings.TrimSuffix(zone, ".")
	out := []string{name}
	if z != "" && name != z && !strings.HasSuffix(name, "."+z) {
		out = append(out, name+"."+z)
	}
	return out
}

// resolveFQDN picks the first candidate FQDN that has an owned domain match.
// Returns the resolved FQDN, the matching domain, and apex.
func resolveFQDN(domains []domain, name, zone string) (string, *domain, string) {
	for _, c := range candidateFQDNs(name, zone) {
		if d, apex := pickDomainForName(domains, c); d != nil {
			return c, d, apex
		}
	}
	return "", nil, ""
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
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
