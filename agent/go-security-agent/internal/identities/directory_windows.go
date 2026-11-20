//go:build windows

package identities

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Event Log API (wevtapi.dll), used remotely and read-only: EvtOpenSession opens an RPC
// session to the domain controller, EvtQuery reads its Security log, EvtRender gives the XML.
var (
	wevtapi            = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtOpenSession = wevtapi.NewProc("EvtOpenSession")
	procEvtQuery       = wevtapi.NewProc("EvtQuery")
	procEvtNext        = wevtapi.NewProc("EvtNext")
	procEvtRender      = wevtapi.NewProc("EvtRender")
	procEvtClose       = wevtapi.NewProc("EvtClose")
)

const (
	evtRPCLogin              = 1
	evtRPCLoginAuthNegotiate = 1
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	errorNoMoreItems         = windows.Errno(259)
	errorInsufficientBuffer  = windows.ERROR_INSUFFICIENT_BUFFER
	nextBatch                = 64
	nextTimeoutMillis        = 30000
)

type evtRPCLoginInfo struct {
	Server   *uint16
	User     *uint16
	Domain   *uint16
	Password *uint16
	Flags    uint32
}

func evtClose(h uintptr) {
	if h != 0 {
		_, _, _ = procEvtClose.Call(h)
	}
}

func readEvents(ctx context.Context, cfg DirectoryConfig, query string, limit int, each func([]byte)) error {
	if err := wevtapi.Load(); err != nil {
		return ErrUnsupported
	}
	server, err := windows.UTF16PtrFromString(cfg.ServerIP().String())
	if err != nil {
		return err
	}
	user, err := windows.UTF16PtrFromString(cfg.User)
	if err != nil {
		return err
	}
	var domain *uint16
	if cfg.Domain != "" {
		if domain, err = windows.UTF16PtrFromString(cfg.Domain); err != nil {
			return err
		}
	}
	password, err := windows.UTF16FromString(cfg.Password)
	if err != nil {
		return err
	}
	defer clear(password)
	login := evtRPCLoginInfo{Server: server, User: user, Domain: domain, Password: &password[0],
		Flags: evtRPCLoginAuthNegotiate}
	session, _, callErr := procEvtOpenSession.Call(evtRPCLogin, uintptr(unsafe.Pointer(&login)), 0, 0)
	if session == 0 {
		return fmt.Errorf("domain controller session: %w", callErr)
	}
	defer evtClose(session)

	channel, _ := windows.UTF16PtrFromString("Security")
	xpath, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return err
	}
	results, _, callErr := procEvtQuery.Call(session, uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(xpath)), evtQueryChannelPath|evtQueryReverseDirection)
	if results == 0 {
		return fmt.Errorf("security log query: %w", callErr)
	}
	defer evtClose(results)

	handles := make([]uintptr, nextBatch)
	buf := make([]uint16, 16*1024)
	read := 0
	for read < limit {
		if err := ctx.Err(); err != nil {
			return err
		}
		var returned uint32
		ok, _, callErr := procEvtNext.Call(results, nextBatch, uintptr(unsafe.Pointer(&handles[0])),
			nextTimeoutMillis, 0, uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			if errors.Is(callErr, errorNoMoreItems) {
				return nil
			}
			return fmt.Errorf("security log read: %w", callErr)
		}
		for _, h := range handles[:returned] {
			if raw, err := render(h, &buf); err == nil {
				each(raw)
			}
			evtClose(h)
			read++
		}
	}
	return nil
}

// render returns the event as UTF-8 XML; buf grows when the event does not fit.
func render(event uintptr, buf *[]uint16) ([]byte, error) {
	for range 2 {
		var used, props uint32
		ok, _, callErr := procEvtRender.Call(0, event, evtRenderEventXML, uintptr(len(*buf)*2),
			uintptr(unsafe.Pointer(&(*buf)[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if ok != 0 {
			return []byte(windows.UTF16ToString((*buf)[:used/2])), nil
		}
		if !errors.Is(callErr, errorInsufficientBuffer) || used/2 <= uint32(len(*buf)) {
			return nil, callErr
		}
		*buf = make([]uint16, used/2+1)
	}
	return nil, errors.New("event too large")
}
