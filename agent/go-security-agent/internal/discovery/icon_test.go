package discovery

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

// mockPNG is a [MOCK] w×h PNG.
func mockPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 200, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// mockIconDevice serves a [MOCK] UPnP description whose iconList has a small and a preferred icon,
// a GIF (not accepted) and, if evil, an icon URL that points to another host.
func mockIconDevice(t *testing.T, evil bool, fetched *atomic.Int32) *httptest.Server {
	small, big := mockPNG(t, 48, 48), mockPNG(t, 120, 120)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/desc.xml":
			icon := "/icons/120.png"
			if evil {
				icon = "http://169.254.169.254/icon.png"
			}
			fmt.Fprintf(w, `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName>MOCK TV</friendlyName>
<manufacturer>MOCK</manufacturer><modelName>TV-1</modelName><iconList>
<icon><mimetype>image/png</mimetype><width>48</width><height>48</height><depth>24</depth><url>/icons/48.png</url></icon>
<icon><mimetype>image/gif</mimetype><width>200</width><height>200</height><depth>8</depth><url>/icons/200.gif</url></icon>
<icon><mimetype>image/png</mimetype><width>120</width><height>120</height><depth>24</depth><url>%s</url></icon>
</iconList></device></root>`, icon)
		case "/icons/48.png":
			fetched.Add(1)
			_, _ = w.Write(small)
		case "/icons/120.png":
			fetched.Add(1)
			_, _ = w.Write(big)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSSDPFetchesTheIconDeclaredByTheDevice(t *testing.T) {
	var fetched atomic.Int32
	srv := mockIconDevice(t, false, &fetched)
	obs := describe(context.Background(), netip.MustParseAddr("127.0.0.1"),
		&ssdpAnswer{types: map[string]bool{}, locations: []string{srv.URL + "/desc.xml"}})
	if len(obs) != 1 || obs[0].Icon == nil {
		t.Fatalf("no icon: %+v", obs)
	}
	icon := obs[0].Icon
	if icon.Origin != "UPNP" || icon.ContentType != "image/png" || icon.Width != 120 || icon.Height != 120 ||
		fetched.Load() != 1 {
		t.Fatalf("unexpected icon %s %s %dx%d fetched=%d", icon.Origin, icon.ContentType, icon.Width, icon.Height,
			fetched.Load())
	}
}

func TestIconURLPointingElsewhereIsNeverFollowed(t *testing.T) {
	var fetched atomic.Int32
	srv := mockIconDevice(t, true, &fetched)
	obs := describe(context.Background(), netip.MustParseAddr("127.0.0.1"),
		&ssdpAnswer{types: map[string]bool{}, locations: []string{srv.URL + "/desc.xml"}})
	if len(obs) != 1 || obs[0].Icon != nil || obs[0].Details["iconRefused"] != true || fetched.Load() != 0 {
		t.Fatalf("icon from another host accepted: %+v fetched=%d", obs, fetched.Load())
	}
}

func TestOnlySmallPNGOrJPEGIconsAreAccepted(t *testing.T) {
	if _, err := validateIcon(mockPNG(t, 64, 64)); err != nil {
		t.Fatalf("valid PNG refused: %v", err)
	}
	for name, data := range map[string][]byte{
		"svg":       []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"html":      []byte("<html><body>MOCK</body></html>"),
		"gif":       []byte("GIF89a\x01\x00\x01\x00"),
		"truncated": []byte("\x89PNG\r\n\x1a\n"),
		"too big":   append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, maxIconBytes)...),
		"huge side": mockPNG(t, maxIconSide+1, 1),
		"empty":     {},
	} {
		if _, err := validateIcon(data); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestChooseIconPrefersTheLargestUpTo256(t *testing.T) {
	icons := []upnpIcon{
		{MimeType: "image/png", Width: "32", URL: "/32.png"},
		{MimeType: "image/jpeg", Width: "240", URL: "/240.jpg"},
		{MimeType: "image/png", Width: "512", URL: "/512.png"},
		{MimeType: "image/bmp", Width: "256", URL: "/256.bmp"},
	}
	if c, ok := chooseIcon(icons); !ok || c.URL != "/240.jpg" {
		t.Fatalf("chose %+v", c)
	}
	if c, ok := chooseIcon(icons[2:]); !ok || c.URL != "/512.png" {
		t.Fatalf("chose %+v", c)
	}
	if _, ok := chooseIcon([]upnpIcon{{MimeType: "image/gif", Width: "48", URL: "/x.gif"}}); ok {
		t.Fatal("GIF chosen")
	}
}
