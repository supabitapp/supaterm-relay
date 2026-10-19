package dashboard

import (
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func unlimited(next http.Handler) http.Handler {
	return next
}

func serve(t *testing.T, d *Dashboard, path string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	maps.Copy(request.Header, header)
	response := httptest.NewRecorder()
	d.ServeHTTP(response, request)
	return response
}

func findRow(t *testing.T, v view, label string) row {
	t.Helper()
	for _, s := range v.Sections {
		for _, r := range s.Rows {
			if r.Label == label {
				return r
			}
		}
	}
	t.Fatalf("no %q row in %+v", label, v.Sections)
	return row{}
}

func TestPageEmbedsCurrentStats(t *testing.T) {
	stats := Stats{ActiveHosts: 3}
	d := New(func() Stats { return stats }, unlimited)
	response := serve(t, d, "/", nil)
	body := response.Body.String()
	if response.Code != http.StatusOK || response.Header().Get("Content-Security-Policy") != contentSecurityPolicy || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("page: %d %v", response.Code, response.Header())
	}
	for _, want := range []string{`hx-get="stats"`, `hx-trigger="every 2s"`, ">Online<", "Connected hosts", `<span class="value">3</span>`, "Traffic (1 min avg)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page is missing %q:\n%s", want, body)
		}
	}
}

func TestStatsFragmentReportsDraining(t *testing.T) {
	stats := Stats{Draining: true}
	body := serve(t, New(func() Stats { return stats }, unlimited), "/stats", nil).Body.String()
	if strings.Contains(body, "<html") || !strings.Contains(body, `class="status draining">Draining<`) {
		t.Fatalf("incorrect stats fragment:\n%s", body)
	}
}

func TestLimitAppliesToPagesNotAssets(t *testing.T) {
	reject := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		})
	}
	d := New(func() Stats { return Stats{} }, reject)
	for path, status := range map[string]int{
		"/":                             http.StatusTooManyRequests,
		"/stats":                        http.StatusTooManyRequests,
		"/static/htmx-2.0.11.min.js":    http.StatusOK,
		"/static/dashboard.js":          http.StatusOK,
		"/static/dashboard.css":         http.StatusOK,
		"/static/missing.js":            http.StatusNotFound,
		"/static/":                      http.StatusNotFound,
		"/templates/page.html":          http.StatusNotFound,
		"/static/..%2ftemplates%2fpage": http.StatusNotFound,
	} {
		response := serve(t, d, path, nil)
		if response.Code != status {
			t.Errorf("%s: status %d, want %d", path, response.Code, status)
		}
		if response.Header().Get("Content-Security-Policy") != contentSecurityPolicy || response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing security headers: %v", path, response.Header())
		}
	}
}

func TestAssetsRevalidateWithETags(t *testing.T) {
	d := New(func() Stats { return Stats{} }, unlimited)
	first := serve(t, d, "/static/htmx-2.0.11.min.js", nil)
	tag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || tag == "" || first.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("asset: %d %v", first.Code, first.Header())
	}
	if again := serve(t, d, "/static/htmx-2.0.11.min.js", http.Header{"If-None-Match": {tag}}); again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Fatalf("revalidation: %d with %d bytes", again.Code, again.Body.Len())
	}
	if other := serve(t, d, "/static/dashboard.js", nil).Header().Get("ETag"); other == tag {
		t.Fatal("distinct assets share an ETag")
	}
}

func TestSnapshotSamplesAtMostOncePerRefresh(t *testing.T) {
	calls := 0
	d := New(func() Stats {
		calls++
		return Stats{}
	}, unlimited)
	for _, offset := range []time.Duration{time.Second, 1500 * time.Millisecond, 1999 * time.Millisecond, 2 * time.Second} {
		d.snapshot(d.started.Add(offset))
	}
	if calls != 2 {
		t.Fatalf("relay sampled %d times, want 2", calls)
	}
}

func TestTrafficRatesAverageTheLastMinute(t *testing.T) {
	stats := Stats{ForwardedMessages: 1200, ForwardedBytes: 1 << 20}
	d := New(func() Stats { return stats }, unlimited)
	initial := d.snapshot(d.started)
	for _, label := range []string{"Messages", "Throughput"} {
		if got := findRow(t, initial, label).Value; got != unknown {
			t.Fatalf("initial %s rate = %q, want unknown", label, got)
		}
	}
	stats.ForwardedMessages += 600
	stats.ForwardedBytes += 60 << 10
	for _, tc := range []struct {
		seconds    int
		messages   string
		throughput string
	}{
		{2, "300/s", "30.0 KiB/s"},
		{5, "120/s", "12.0 KiB/s"},
		{10, "60/s", "6.0 KiB/s"},
		{20, "30/s", "3.0 KiB/s"},
		{30, "20/s", "2.0 KiB/s"},
		{40, "15/s", "1.5 KiB/s"},
		{50, "12/s", "1.2 KiB/s"},
		{60, "10/s", "1.0 KiB/s"},
		{62, "0.0/s", "0 B/s"},
	} {
		v := d.snapshot(d.started.Add(time.Duration(tc.seconds) * time.Second))
		for label, want := range map[string]row{
			"Messages":   {Label: "Messages", Value: tc.messages, Detail: "1,800 total"},
			"Throughput": {Label: "Throughput", Value: tc.throughput, Detail: "1.1 MiB total"},
		} {
			if got := findRow(t, v, label); got != want {
				t.Errorf("at %ds: %s = %+v, want %+v", tc.seconds, label, got, want)
			}
		}
	}
}

func TestTrafficRatesRestartAfterGapsOrCounterResets(t *testing.T) {
	for _, reason := range []string{"monitoring gap", "messages reset", "bytes reset"} {
		t.Run(reason, func(t *testing.T) {
			stats := Stats{ForwardedMessages: 1000, ForwardedBytes: 1 << 20}
			d := New(func() Stats { return stats }, unlimited)
			d.snapshot(d.started)
			stats.ForwardedMessages += 20
			stats.ForwardedBytes += 2048
			d.snapshot(d.started.Add(2 * time.Second))
			at := d.started.Add(4 * time.Second)
			switch reason {
			case "monitoring gap":
				at = d.started.Add(time.Hour)
				stats.ForwardedMessages += 5000
				stats.ForwardedBytes += 1 << 20
			case "messages reset":
				stats.ForwardedMessages = 0
			case "bytes reset":
				stats.ForwardedBytes = 0
			}
			v := d.snapshot(at)
			for _, label := range []string{"Messages", "Throughput"} {
				if got := findRow(t, v, label).Value; got != unknown {
					t.Fatalf("after %s: %s rate = %q, want unknown", reason, label, got)
				}
			}
			stats.ForwardedMessages += 40
			stats.ForwardedBytes += 4096
			v = d.snapshot(at.Add(2 * time.Second))
			for label, want := range map[string]string{"Messages": "20/s", "Throughput": "2.0 KiB/s"} {
				if got := findRow(t, v, label).Value; got != want {
					t.Errorf("resumed %s rate = %q, want %q", label, got, want)
				}
			}
		})
	}
}

func TestBuildReportsCPUOverTheSampleWindow(t *testing.T) {
	d := &Dashboard{started: time.Now()}
	previous := sample{at: d.started, cpuOK: true, cpus: 4}
	current := previous
	current.at = previous.at.Add(2 * time.Second)
	current.cpu = time.Second
	want := row{Label: "Relay process", Value: "12.5%", Detail: "of 4 cores", Level: 0.125, Meter: true}
	if got := findRow(t, d.build(previous, current), "Relay process"); got != want {
		t.Errorf("Relay process = %+v, want %+v", got, want)
	}
}

func TestBuildOmitsRatesAfterAQuietPeriod(t *testing.T) {
	d := &Dashboard{started: time.Now()}
	previous := sample{at: d.started, cpuOK: true, cpus: 1}
	current := previous
	current.at = previous.at.Add(time.Hour)
	current.relay.ForwardedMessages = 3600
	v := d.build(previous, current)
	for _, label := range []string{"Messages", "Throughput", "Relay process"} {
		if got := findRow(t, v, label); got.Value != unknown || got.Meter {
			t.Errorf("%s = %+v, want an unknown rate", label, got)
		}
	}
	if got := findRow(t, v, "Relay process").Detail; got != "of 1 core" {
		t.Errorf("core detail = %q", got)
	}
}

func TestBuildGaugesMemoryLimits(t *testing.T) {
	d := &Dashboard{started: time.Now()}
	current := sample{
		at:          d.started,
		retained:    1 << 30,
		memoryLimit: 2 << 30,
		systemOK:    true,
		systemUsed:  3 << 30,
		systemTotal: 4 << 30,
	}
	v := d.build(current, current)
	for label, want := range map[string]row{
		"Go runtime": {Label: "Go runtime", Value: "1.0 GiB", Detail: "of 2.0 GiB limit", Level: 0.5, Meter: true},
		"System":     {Label: "System", Value: "3.0 GiB", Detail: "of 4.0 GiB", Level: 0.75, Meter: true},
	} {
		if got := findRow(t, v, label); got != want {
			t.Errorf("%s = %+v, want %+v", label, got, want)
		}
	}
	current.memoryLimit = math.MaxInt64
	if got := findRow(t, d.build(current, current), "Go runtime"); got.Meter || got.Detail != "" {
		t.Errorf("unlimited runtime memory = %+v", got)
	}
}

func TestGaugeClampsMeterLevel(t *testing.T) {
	for _, tc := range []struct{ in, level float64 }{{-0.5, 0}, {0.5, 0.5}, {1.2, 1}} {
		if got := gauge("memory", "", "", tc.in); !got.Meter || got.Level != tc.level {
			t.Errorf("gauge(%v) = %+v, want level %v", tc.in, got, tc.level)
		}
	}
}

func TestParseLoadAverage(t *testing.T) {
	if load, ok := parseLoadAverage("0.52 1.04 2.00 2/345 6789\n"); !ok || load != [3]float64{0.52, 1.04, 2} {
		t.Fatalf("parseLoadAverage = %v, %v", load, ok)
	}
	for _, invalid := range []string{"", "0.1 0.2", "0.1 x 0.3"} {
		if _, ok := parseLoadAverage(invalid); ok {
			t.Errorf("parseLoadAverage(%q) succeeded", invalid)
		}
	}
}

func TestParseMeminfo(t *testing.T) {
	const meminfo = "MemTotal:        4026412 kB\nMemFree:          123456 kB\nMemAvailable:    3026412 kB\n"
	used, total, ok := parseMeminfo(meminfo)
	if !ok || total != 4026412<<10 || used != 1000000<<10 {
		t.Fatalf("parseMeminfo = %d, %d, %v", used, total, ok)
	}
	for _, invalid := range []string{"", "MemTotal: 10 kB\n", "MemTotal: 10 kB\nMemAvailable: 20 kB\n", "MemTotal: x kB\nMemAvailable: 1 kB\n"} {
		if _, _, ok := parseMeminfo(invalid); ok {
			t.Errorf("parseMeminfo(%q) succeeded", invalid)
		}
	}
}

func TestRejectionRowsListTheTotalThenEachReason(t *testing.T) {
	got := rejectionRows(1495, map[string]int64{"rate limited": 3, "endpoint not found": 1489, "invalid token": 3})
	want := []row{
		{Label: "Total", Value: "1,495", Detail: "since start"},
		{Label: "Endpoint not found", Value: "1,489"},
		{Label: "Invalid token", Value: "3"},
		{Label: "Rate limited", Value: "3"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("rejectionRows = %+v, want %+v", got, want)
	}
	if got := rejectionRows(0, nil); !slices.Equal(got, []row{{Label: "Total", Value: "0", Detail: "since start"}}) {
		t.Fatalf("no rejections = %+v", got)
	}
}
