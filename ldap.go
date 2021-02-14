package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"github.com/lor00x/goldap/message"
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

func matchFilter(filter message.Filter, attrs map[string][]message.AttributeValue) bool {
	switch f := filter.(type) {
	case message.FilterAnd:
		for _, child := range f {
			match := matchFilter(child, attrs)
			if !match {
				return false
			}
		}
		return true
	case message.FilterOr:
		for _, child := range f {
			match := matchFilter(child, attrs)
			if match {
				return true
			}
		}
		return false
	case message.FilterNot:
		return !matchFilter(f.Filter, attrs)
	case message.FilterSubstrings:
		for k, vals := range attrs {
			if strings.EqualFold(k, string(f.Type_())) {
				for _, val := range vals {
					v := string(val)
					match := true
					for _, fs := range f.Substrings() {
						switch fsv := fs.(type) {
						case message.SubstringInitial:
							if !strings.HasPrefix(v, string(fsv)) {
								match = false
							}
						case message.SubstringAny:
							if !strings.Contains(v, string(fsv)) {
								match = false
							}
						case message.SubstringFinal:
							if !strings.HasSuffix(v, string(fsv)) {
								match = false
							}
						}
					}
					if match {
						return true
					}
				}
				// vals not match
				return false
			}
		}
		// key not found
		return false
	case message.FilterEqualityMatch:
		for k, vals := range attrs {
			if strings.EqualFold(k, string(f.AttributeDesc())) {
				for _, val := range vals {
					v := string(val)
					if strings.EqualFold(v, string(f.AssertionValue())) {
						return true
					}
				}
				// vals not match
				return false
			}
		}
		// key not found
		return false
	case message.FilterPresent:
		for k := range attrs {
			if strings.EqualFold(k, string(f)) {
				// found key
				return true
			}
		}
		// key not found
		return false
	default:
		// TODO
		return false
	}
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	if r.BaseObject() == "" && r.Scope() == ldap.SearchRequestScopeBaseObject && strings.ToLower(r.FilterString()) == "(objectclass=*)" {
		// server specific data
		// https://tools.ietf.org/html/rfc4512#section-5.1
		res := ldap.NewSearchResultEntry("")
		res.AddAttribute("supportedSASLMechanisms")
		w.Write(res)
		w.Write(ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess))
	} else {
		log.Printf("Search base=%s filter=%s", r.BaseObject(), r.FilterString())
		parts := getParts(string(r.BaseObject()))
		key := strings.Join(parts, ",")
		resp, err := kvc.Get(context.Background(), key+",", clientv3.WithPrefix())
		if err != nil {
			log.Printf("Failed to search entry %s: %s", key, err)
			res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOther)
			w.Write(res)
			return
		}

		count := 0
		for i := range resp.Kvs {
			key := string(resp.Kvs[i].Key)
			parts := getParts(key)
			res := ldap.NewSearchResultEntry(strings.Join(parts, ","))
			var value map[string][]message.AttributeValue
			err := json.Unmarshal(resp.Kvs[i].Value, &value)
			if err != nil {
				log.Printf("Failed to unmarshal json: %s", err)
				continue
			}

			if !matchFilter(r.Filter(), value) {
				continue
			}

			for k, v := range value {
				res.AddAttribute(message.AttributeDescription(k), v...)
			}
			w.Write(res)
			count = count + 1
		}
		log.Printf("Return %d search entries", count)
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
		w.Write(res)
	}
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
	attrs := make(map[string][]message.AttributeValue)
	for _, v := range r.Attributes() {
		attrs[string(v.Type_())] = v.Vals()
	}
	val, err := json.Marshal(attrs)
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

func handleAbandon(w ldap.ResponseWriter, m *ldap.Message) {
}
