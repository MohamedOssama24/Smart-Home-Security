package identity

// MatchOwner is not needed on Windows: files inherit the ACL of the state directory, which
// already grants access to the service account (LocalService).
func (s Store) MatchOwner() error {
	return nil
}
