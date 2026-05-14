package domeneshop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

// --- pickDomainForName ------------------------------------------------------

func TestPickDomainForName(t *testing.T) {
	domains := []domain{
		{ID: 1, Name: "ybmn.no"},
		{ID: 2, Name: "sletteposten.no"},
		{ID: 3, Name: "yesbutmaybe.no"},
		{ID: 4, Name: "deep.ybmn.no"}, // contrived sub-domain registered separately
	}

	cases := []struct {
		name     string
		input    string
		wantName string // empty = expect no match
	}{
		{"exact apex match", "ybmn.no", "ybmn.no"},
		{"single subdomain", "cloud.ybmn.no", "ybmn.no"},
		{"deep ACME challenge", "_acme-challenge.cloud.ybmn.no", "ybmn.no"},
		{"trailing dot", "cloud.ybmn.no.", "ybmn.no"},
		{"uppercase input", "Cloud.YBMN.No", "ybmn.no"},
		{"longest-suffix wins", "_acme-challenge.deep.ybmn.no", "deep.ybmn.no"},
		{"other owned domain", "mail.sletteposten.no", "sletteposten.no"},
		{"unrelated domain", "example.com", ""},
		{"bare TLD must not match", "no", ""},
		{"trailing-dot TLD must not match", "no.", ""},
		{"substring is not suffix", "notybmn.no", ""}, // would only match if we did naive Contains
		{"empty input", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, apex := pickDomainForName(domains, tc.input)
			if tc.wantName == "" {
				if d != nil {
					t.Fatalf("expected no match for %q, got %q", tc.input, d.Name)
				}
				if apex != "" {
					t.Fatalf("expected empty apex for %q, got %q", tc.input, apex)
				}
				return
			}
			if d == nil {
				t.Fatalf("expected match %q for %q, got nil", tc.wantName, tc.input)
			}
			if d.Name != tc.wantName {
				t.Fatalf("for %q: want %q, got %q", tc.input, tc.wantName, d.Name)
			}
			if apex != tc.wantName {
				t.Fatalf("for %q: apex want %q, got %q", tc.input, tc.wantName, apex)
			}
		})
	}
}

// --- zoneToApex (backwards-compat path) -------------------------------------

func TestZoneToApex(t *testing.T) {
	cases := map[string]string{
		"ybmn.no":                       "ybmn.no",
		"ybmn.no.":                      "ybmn.no",
		"cloud.ybmn.no":                 "ybmn.no",
		"_acme-challenge.cloud.ybmn.no": "ybmn.no",
		"no":                            "no",
		"no.":                           "no",
		"":                              "",
	}
	for in, want := range cases {
		if got := zoneToApex(in); got != want {
			t.Errorf("zoneToApex(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- end-to-end Append/Delete with a fake domeneshop API --------------------

// newTestServer spins up an httptest server that mimics the parts of the
// domeneshop API we use: GET /domains, GET/POST/DELETE /domains/{id}/dns.
// It records the last create body and the IDs that were deleted so tests
// can assert what the plugin actually sent.
type fakeAPI struct {
	t           *testing.T
	domains     []domain
	dns         map[int][]dnsRecord // by domain ID
	nextID      int
	lastCreated *dnsRecord
	deletedIDs  []int
}

func newFakeAPI(t *testing.T, domains []domain, existing map[int][]dnsRecord) *httptest.Server {
	api := &fakeAPI{
		t:       t,
		domains: domains,
		dns:     existing,
		nextID:  1000,
	}
	srv := httptest.NewServer(http.HandlerFunc(api.handle))
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		// expose final state on cleanup for debugging if needed
		_ = api
	})
	// Expose api on server.Config so tests can inspect after.
	srv.Config.ConnContext = nil
	return srv
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	// Auth check
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" || pass == "" {
		http.Error(w, "no auth", http.StatusUnauthorized)
		return
	}

	switch {
	case r.Method == "GET" && r.URL.Path == "/domains":
		_ = json.NewEncoder(w).Encode(f.domains)
		return

	case strings.HasPrefix(r.URL.Path, "/domains/") && strings.HasSuffix(r.URL.Path, "/dns"):
		var id int
		fmt.Sscanf(r.URL.Path, "/domains/%d/dns", &id)
		switch r.Method {
		case "GET":
			_ = json.NewEncoder(w).Encode(f.dns[id])
		case "POST":
			var rec dnsRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = f.nextID
			f.nextID++
			f.dns[id] = append(f.dns[id], rec)
			f.lastCreated = &rec
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return

	case strings.HasPrefix(r.URL.Path, "/domains/") && r.Method == "DELETE":
		var domID, recID int
		fmt.Sscanf(r.URL.Path, "/domains/%d/dns/%d", &domID, &recID)
		filtered := f.dns[domID][:0]
		found := false
		for _, e := range f.dns[domID] {
			if e.ID == recID {
				found = true
				continue
			}
			filtered = append(filtered, e)
		}
		f.dns[domID] = filtered
		if found {
			f.deletedIDs = append(f.deletedIDs, recID)
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
		return
	}
	http.Error(w, "unhandled "+r.Method+" "+r.URL.Path, http.StatusNotFound)
}

// withBaseURL temporarily swaps the package-level baseURL for the duration
// of a test. The plugin's `newClient` uses the package const directly, so we
// patch it via a test-local helper.
func withBaseURL(t *testing.T, url string, fn func()) {
	orig := baseURLVar
	baseURLVar = url
	t.Cleanup(func() { baseURLVar = orig })
	fn()
}

// This reproduces the real-world certmagic call: zone="no." (the broken
// upstream finder) and Name relative to that zone (so the ".no" tail is
// already chopped off). The plugin must reconstruct the FQDN and still
// find ybmn.no.
func TestAppendRecords_RelativeNameAgainstBogusZone(t *testing.T) {
	api := &fakeAPI{
		t:       t,
		domains: []domain{{ID: 42, Name: "ybmn.no"}, {ID: 7, Name: "sletteposten.no"}},
		dns:     map[int][]dnsRecord{42: nil, 7: nil},
		nextID:  1000,
	}
	srv := httptest.NewServer(http.HandlerFunc(api.handle))
	defer srv.Close()

	withBaseURL(t, srv.URL, func() {
		p := &Provider{APIToken: "tok", APISecret: "sec"}
		_, err := p.AppendRecords(context.Background(), "no.", []libdns.Record{
			libdns.RR{
				Name: "_acme-challenge.cloud.ybmn", // relative to zone "no."
				Type: "TXT",
				Data: "challenge-data",
			},
		})
		if err != nil {
			t.Fatalf("AppendRecords failed: %v", err)
		}
		if api.lastCreated == nil {
			t.Fatal("expected a record to be created")
		}
		if api.lastCreated.Host != "_acme-challenge.cloud" {
			t.Errorf("relative host wrong: got %q, want %q",
				api.lastCreated.Host, "_acme-challenge.cloud")
		}
		if len(api.dns[42]) != 1 {
			t.Errorf("expected record under domain 42 (ybmn.no), got %d", len(api.dns[42]))
		}
	})
}

func TestAppendRecords_PicksRightDomainDespiteMisleadingZone(t *testing.T) {
	api := &fakeAPI{
		t:       t,
		domains: []domain{{ID: 42, Name: "ybmn.no"}, {ID: 7, Name: "sletteposten.no"}},
		dns:     map[int][]dnsRecord{42: nil, 7: nil},
		nextID:  1000,
	}
	srv := httptest.NewServer(http.HandlerFunc(api.handle))
	defer srv.Close()

	withBaseURL(t, srv.URL, func() {
		p := &Provider{APIToken: "tok", APISecret: "sec"}
		// Note: zone here is the broken "no." that certmagic was passing.
		// The plugin should ignore it and use the FQDN to pick ybmn.no.
		_, err := p.AppendRecords(context.Background(), "no.", []libdns.Record{
			libdns.RR{
				Name: "_acme-challenge.cloud.ybmn.no.",
				Type: "TXT",
				Data: "challenge-data",
			},
		})
		if err != nil {
			t.Fatalf("AppendRecords failed: %v", err)
		}
		if api.lastCreated == nil {
			t.Fatal("expected a record to be created")
		}
		if api.lastCreated.Host != "_acme-challenge.cloud" {
			t.Errorf("relative host wrong: got %q, want %q",
				api.lastCreated.Host, "_acme-challenge.cloud")
		}
		if api.lastCreated.Type != "TXT" || api.lastCreated.Data != "challenge-data" {
			t.Errorf("record body wrong: %+v", api.lastCreated)
		}
		if len(api.dns[42]) != 1 {
			t.Errorf("expected record under domain 42 (ybmn.no), got %d", len(api.dns[42]))
		}
		if len(api.dns[7]) != 0 {
			t.Errorf("expected no records under domain 7 (sletteposten.no), got %d", len(api.dns[7]))
		}
	})
}

func TestDeleteRecords_RemovesMatching(t *testing.T) {
	api := &fakeAPI{
		t:       t,
		domains: []domain{{ID: 42, Name: "ybmn.no"}},
		dns: map[int][]dnsRecord{
			42: {
				{ID: 500, Host: "_acme-challenge.cloud", Type: "TXT", Data: "old-data"},
				{ID: 501, Host: "www", Type: "A", Data: "10.0.0.1"},
			},
		},
		nextID: 1000,
	}
	srv := httptest.NewServer(http.HandlerFunc(api.handle))
	defer srv.Close()

	withBaseURL(t, srv.URL, func() {
		p := &Provider{APIToken: "tok", APISecret: "sec"}
		_, err := p.DeleteRecords(context.Background(), "ignored", []libdns.Record{
			libdns.RR{Name: "_acme-challenge.cloud.ybmn.no.", Type: "TXT", Data: "old-data"},
		})
		if err != nil {
			t.Fatalf("DeleteRecords failed: %v", err)
		}
		if len(api.deletedIDs) != 1 || api.deletedIDs[0] != 500 {
			t.Errorf("expected to delete id 500, deleted %v", api.deletedIDs)
		}
		// The unrelated A record should still be present.
		if len(api.dns[42]) != 1 || api.dns[42][0].ID != 501 {
			t.Errorf("unexpected remaining records: %+v", api.dns[42])
		}
	})
}

func TestAppendRecords_NoMatchingDomainErrors(t *testing.T) {
	api := &fakeAPI{
		t:       t,
		domains: []domain{{ID: 42, Name: "ybmn.no"}},
		dns:     map[int][]dnsRecord{42: nil},
	}
	srv := httptest.NewServer(http.HandlerFunc(api.handle))
	defer srv.Close()

	withBaseURL(t, srv.URL, func() {
		p := &Provider{APIToken: "tok", APISecret: "sec"}
		_, err := p.AppendRecords(context.Background(), "anything", []libdns.Record{
			libdns.RR{Name: "thing.example.com.", Type: "TXT", Data: "x"},
		})
		if err == nil {
			t.Fatal("expected error for FQDN that doesn't match any owned domain")
		}
		if !strings.Contains(err.Error(), "example.com") {
			t.Errorf("error should mention the offending FQDN; got: %v", err)
		}
	})
}
