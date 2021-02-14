package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	ldap "github.com/vjeantet/ldapserver"
	"go.etcd.io/etcd/clientv3"
)

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	// TODO: auth

	log.Printf("Got bind request: %s %s", r.Name(), r.AuthenticationSimple())

	w.Write(res)
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)

	w.Write(res)
}

func getParts(s string) []string {
	parts := strings.Split(s, ",")
	res := make([]string, len(parts))
	for i := range parts {
		res[len(parts)-i-1] = strings.TrimSpace(parts[i])
	}
	return res
}

func handleAdd(w ldap.ResponseWriter, m *ldap.Message) {
	// https://tools.ietf.org/html/rfc4511#section-4.7
	r := m.GetAddRequest()
	parts := getParts(string(r.Entry()))
	txn := kvc.Txn(context.Background())

	key := strings.Join(parts, ",")
	// check if parent exists
	if len(parts) > 1 {
		parent := strings.Join(parts[:len(parts)-1], ",")
		txn = txn.If(clientv3.Compare(clientv3.CreateRevision(parent), ">", 0),
			clientv3.Compare(clientv3.CreateRevision(key), "=", 0))
	} else {
		txn = txn.If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0))
	}

	// does not override
	val, err := json.Marshal(r.Attributes())
	if err != nil {
		log.Printf("Got error when marshal attributes into json: %s", err)
		res := ldap.NewAddResponse(ldap.LDAPResultUnavailable)
		w.Write(res)
		return
	}

	txn = txn.Then(clientv3.OpPut(key, string(val)))
	txn = txn.Else(clientv3.OpGet(key))
	resp, err := txn.Commit()

	if err != nil {
		log.Printf("Got error when add request: %s", err)
		res := ldap.NewAddResponse(ldap.LDAPResultUnavailable)
		w.Write(res)
	} else {
		if resp.Succeeded {
			// success
			log.Printf("Add entry: %s", key)
			res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
			w.Write(res)
		} else {
			if resp.Responses[0].GetResponseRange().GetCount() > 0 {
				// already exists
				log.Printf("Failed to add entry %s: already exists", key)
				res := ldap.NewAddResponse(ldap.LDAPResultEntryAlreadyExists)
				w.Write(res)
			} else {
				// parent does not exist
				log.Printf("Failed to add entry %s: parent does not exist", key)
				res := ldap.NewAddResponse(ldap.LDAPResultNoSuchObject)
				w.Write(res)
			}
		}
	}
}

func handleDelete(w ldap.ResponseWriter, m *ldap.Message) {
	// https://tools.ietf.org/html/rfc4511#section-4.8
	r := m.GetDeleteRequest()
	parts := getParts(string(r))

	key := strings.Join(parts, ",")
	// TODO: check if children exist
	resp, err := kvc.Delete(context.Background(), key)
	if err != nil {
		log.Printf("Failed to delete entry %s: %s", key, err)
		res := ldap.NewDeleteResponse(ldap.LDAPResultOther)
		w.Write(res)
	} else {
		if resp.Deleted > 0 {
			log.Printf("Entry deleted %s", err)
			res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
			w.Write(res)
		} else {
			log.Printf("Failed to delete nonexistent entry %s", key)
			res := ldap.NewDeleteResponse(ldap.LDAPResultNoSuchObject)
			w.Write(res)
		}
	}
}
