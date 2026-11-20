package discovery

import (
	"bytes"
	"context"
	"errors"
	"image"
	_ "image/jpeg" // registers the decoder used only to read the header (DecodeConfig)
	_ "image/png"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Device icon (M23, ADR-077): the picture a UPnP device declares about itself in <iconList>.
// It is fetched with the same rules as the description (safeURL + deviceClient): only from the
// device's own address on an authorized target, no redirects, no proxy, 3 s. Only PNG and JPEG,
// recognized by their magic bytes, at most maxIconBytes and maxIconSide pixels per side; the
// pixels are never decoded, only the header.

const (
	maxIconBytes = 32 << 10
	maxIconSide  = 1024
	// preferred size: the largest icon not above this side, otherwise the smallest one
	preferredIconSide = 256
)

// Icon is a validated device icon.
type Icon struct {
	Origin      string // UPNP
	ContentType string // image/png | image/jpeg
	Width       int
	Height      int
	Data        []byte
}

type upnpIcon struct {
	MimeType string `xml:"mimetype"`
	Width    string `xml:"width"`
	Height   string `xml:"height"`
	URL      string `xml:"url"`
}

var errBadIcon = errors.New("icon refused: not a small PNG or JPEG")

// chooseIcon picks the PNG/JPEG icon closest to preferredIconSide (largest not above it,
// otherwise the smallest), PNG preferred at equal size.
func chooseIcon(icons []upnpIcon) (upnpIcon, bool) {
	best, found := upnpIcon{}, false
	score := func(i upnpIcon) (int, bool) {
		mt := strings.ToLower(strings.TrimSpace(i.MimeType))
		if mt != "image/png" && mt != "image/jpeg" && mt != "image/jpg" {
			return 0, false
		}
		w, _ := strconv.Atoi(strings.TrimSpace(i.Width))
		if w <= 0 || w > maxIconSide || strings.TrimSpace(i.URL) == "" {
			return 0, false
		}
		s := w * 2
		if w > preferredIconSide {
			s = -w * 2 // above the preference: the smaller the better
		}
		if mt == "image/png" {
			s++
		}
		return s, true
	}
	bestScore := 0
	for _, i := range icons {
		if s, ok := score(i); ok && (!found || s > bestScore) {
			best, bestScore, found = i, s, true
		}
	}
	return best, found
}

// fetchIcon downloads the chosen icon of the device; base is the description URL (or URLBase).
func fetchIcon(ctx context.Context, client *http.Client, base *url.URL, icons []upnpIcon, device netip.Addr) (*Icon, error) {
	chosen, ok := chooseIcon(icons)
	if !ok {
		return nil, errBadIcon
	}
	u, err := safeURL(base, chosen.URL, device)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{Status: resp.StatusCode, Header: resp.Header}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIconBytes+1))
	if err != nil {
		return nil, err
	}
	return validateIcon(data)
}

// validateIcon accepts only PNG or JPEG (magic bytes) within the size limits.
func validateIcon(data []byte) (*Icon, error) {
	if len(data) == 0 || len(data) > maxIconBytes {
		return nil, errBadIcon
	}
	var contentType, format string
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		contentType, format = "image/png", "png"
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		contentType, format = "image/jpeg", "jpeg"
	default:
		return nil, errBadIcon
	}
	cfg, f, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || f != format || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxIconSide ||
		cfg.Height > maxIconSide {
		return nil, errBadIcon
	}
	return &Icon{Origin: "UPNP", ContentType: contentType, Width: cfg.Width, Height: cfg.Height, Data: data}, nil
}
