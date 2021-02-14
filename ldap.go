package main

import (
	ldap "github.com/vjeantet/ldapserver"
)

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	// TODO: auth
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	w.Write(res)
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)

	w.Write(res)
}
