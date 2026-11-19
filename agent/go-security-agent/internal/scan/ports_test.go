package scan

import (
	"net/netip"
	"testing"
	"time"

	"shsc/agent/internal/discovery"
	"shsc/agent/internal/portscan"
)

func portLimits() map[string]any {
	return map[string]any{"maxHosts": 1024, "ratePerSecond": 50, "concurrency": 16, "maxDurationSeconds": 1800,
		"ports": map[string]any{"ratePerSecond": 300, "concurrency": 256, "perHostConcurrency": 8,
			"perHostRatePerSecond": 50, "timeoutMillis": 1500}}
}

func TestVerifyPortProfiles(t *testing.T) {
	priv, pub := testKey(t)
	for _, profile := range []string{"QUICK", "STANDARD"} {
		job, err := Verify(sign(t, priv, jobPayload(func(j map[string]any) {
			j["profile"], j["limits"] = profile, portLimits()
		})), pub, testAgent, time.Now())
		if err != nil || job.Limits.Ports == nil || job.Limits.Ports.TimeoutMillis != 1500 {
			t.Fatalf("%s: %v", profile, err)
		}
	}
	tooFast := portLimits()
	tooFast["ports"].(map[string]any)["ratePerSecond"] = 5000
	for name, mutate := range map[string]func(map[string]any){
		"no port limits":    func(j map[string]any) { j["profile"] = "QUICK" },
		"limits over max":   func(j map[string]any) { j["profile"], j["limits"] = "QUICK", tooFast },
		"deferred profile":  func(j map[string]any) { j["profile"], j["limits"] = "DEEP", portLimits() },
		"custom port lists": func(j map[string]any) { j["profile"], j["limits"] = "CUSTOM", portLimits() },
	} {
		if _, err := Verify(sign(t, priv, jobPayload(mutate)), pub, testAgent, time.Now()); err == nil {
			t.Errorf("%s: job accepted", name)
		}
	}
}

func TestScanTargetsSkipSelfAndLinkLocal(t *testing.T) {
	ip := netip.MustParseAddr
	obs := []discovery.Observation{
		{IP: ip("192.168.50.10"), Method: discovery.MethodSelf},
		{IP: ip("192.168.50.10"), Method: "ARP"},
		{IP: ip("192.168.50.20"), Method: "ARP"},
		{IP: ip("192.168.50.20"), Method: "MDNS"},
		{IP: ip("192.168.50.3"), Method: "ICMP"},
		{IP: ip("fe80::1"), Method: "NDP"},
	}
	got := scanTargets(obs)
	if len(got) != 2 || got[0] != ip("192.168.50.3") || got[1] != ip("192.168.50.20") {
		t.Fatalf("targets %v", got)
	}
	sums := summaryObservations(Job{Profile: "QUICK"}, []portscan.Summary{{IP: ip("192.168.50.3"),
		TCP: portscan.Counters{Probed: 40, Open: 1, Closed: 39}}}, time.Now())
	if len(sums) != 1 || sums[0].Method != MethodPortScan || sums[0].Details["tcp"].(map[string]int)["open"] != 1 {
		t.Fatalf("summary %+v", sums)
	}
}
