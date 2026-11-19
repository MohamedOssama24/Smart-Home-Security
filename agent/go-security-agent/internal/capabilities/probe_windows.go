package capabilities

import (
	"golang.org/x/sys/windows"
)

var (
	iphlpapi          = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate    = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose     = iphlpapi.NewProc("IcmpCloseHandle")
	procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable2")
)

// probe on Windows: ARP and ICMP go through the IP Helper API (SendARP/GetIpNetTable2,
// IcmpSendEcho), available to the LocalService account without Npcap or administrator rights.
func probe() Report {
	r := Report{Privileged: windows.GetCurrentProcessToken().IsElevated(), ARP: Unavailable, ICMP: Unavailable}
	if procGetIpNetTable.Find() == nil {
		r.ARP = OSAPI
	}
	if procIcmpCreate.Find() == nil && procIcmpClose.Find() == nil {
		// open and close an ICMP handle: nothing is sent
		handle, _, _ := procIcmpCreate.Call()
		if windows.Handle(handle) != windows.InvalidHandle && handle != 0 {
			procIcmpClose.Call(handle)
			r.ICMP = OSAPI
		}
	}
	return r
}
