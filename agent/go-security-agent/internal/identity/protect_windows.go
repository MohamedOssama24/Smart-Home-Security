package identity

import (
	"bytes"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the private key file is encrypted with DPAPI in machine scope (it cannot be
// decrypted on another computer, so a copied file is useless) and the state directory gets
// an explicit, non-inherited ACL: SYSTEM, Administrators, LocalService (the account of the
// Windows service) and the account that enrolled the agent.

var dpapiEntropy = []byte("shsc-agent-identity-v1")

func protectKey(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty key")
	}
	out, err := dpapi(plain, true)
	if err != nil {
		return nil, fmt.Errorf("protect key with DPAPI: %w", err)
	}
	return append([]byte(dpapiMagic), out...), nil
}

func unprotectKey(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte(dpapiMagic)) {
		return data, nil // key written before DPAPI protection (Milestone 3)
	}
	out, err := dpapi(data[len(dpapiMagic):], false)
	if err != nil {
		return nil, fmt.Errorf("decrypt key with DPAPI (was it copied from another computer?): %w", err)
	}
	return out, nil
}

func dpapi(in []byte, protect bool) ([]byte, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	blobIn := windows.DataBlob{Size: uint32(len(in)), Data: &in[0]}
	entropy := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var blobOut windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN | windows.CRYPTPROTECT_LOCAL_MACHINE)
	var err error
	if protect {
		err = windows.CryptProtectData(&blobIn, nil, &entropy, 0, nil, flags, &blobOut)
	} else {
		err = windows.CryptUnprotectData(&blobIn, nil, &entropy, 0, nil, flags, &blobOut)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(blobOut.Data)))
	return bytes.Clone(unsafe.Slice(blobOut.Data, blobOut.Size)), nil
}

func secureDir(dir string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current user: %w", err)
	}
	// P = protected (no inheritance from ProgramData); OICI = inherited by files and subfolders
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LS)(A;OICI;FA;;;" + user.User.Sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
