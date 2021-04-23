package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/lor00x/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
	"go.etcd.io/etcd/clientv3"
)

// the map from m.Client.Numero to DN bound
var bindDN map[int]string = make(map[int]string)

// root user bind dn
const rootDN = "uid=root"

func normalizeDN(s string) string {
	parts := strings.Split(s, ",")
	res := make([]string, len(parts))
	for i := range parts {
		res[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, ",")
}

func getParts(s string) []string {
	parts := strings.Split(s, ",")
	res := make([]string, len(parts))
	for i := range parts {
		res[len(parts)-i-1] = strings.TrimSpace(parts[i])
	}
	return res
}

func getKey(s string) string {
	parts := getParts(s)
	return strings.Join(parts, ",")
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()

	if r.AuthenticationChoice() != "simple" {
		res := ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
		w.Write(res)
		return
	}

	if r.Name() == rootDN {
		// bind to root
		pass := config.RootPassword
		if crypt.IsHashSupported(pass) {
			crypt := crypt.NewFromHash(pass)
			err := crypt.Verify(pass, r.AuthenticationSimple().Bytes())
			if err == nil {
				// success
				log.Printf("[%s]Bind success: name=%s", m.Client.Addr(), r.Name())

				bindDN[m.Client.Numero] = normalizeDN(string(r.Name()))

				w.Write(ldap.NewBindResponse(ldap.LDAPResultSuccess))
				return
			}
		}

		w.Write(ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials))
		return
	}

	key := getKey(string(r.Name()))

	resp, err := kvc.Get(context.Background(), key)
	if err != nil {
		goto fail
	}

	for _, kv := range resp.Kvs {
		var value map[string][]message.AttributeValue
		err := json.Unmarshal(kv.Value, &value)
		if err != nil {
			log.Printf("Failed to unmarshal json: %s", err)
			continue
		}

		if vals, ok := value["userPassword"]; ok {
			for _, pass := range vals {
				pass := string(pass)
				if strings.HasPrefix(pass, "{crypt}") {
					pass = strings.TrimPrefix(pass, "{crypt}")
					if !crypt.IsHashSupported(pass) {
						continue
					}

					crypt := crypt.NewFromHash(pass)
					err := crypt.Verify(pass, r.AuthenticationSimple().Bytes())
					if err == nil {
						// success
						log.Printf("[%s]Bind success: name=%s", m.Client.Addr(), r.Name())

						bindDN[m.Client.Numero] = normalizeDN(string(r.Name()))
						res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
						w.Write(res)
						return
					}
				}
			}
		}

	}

fail:
	// fail
	log.Printf("[%s]Bind failed: name=%s", m.Client.Addr(), r.Name())

	res := ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials)
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
		eq := equalityMap["default"]
		if sch, ok := schemaMap[string(f.AttributeDesc())]; ok {
			if fun, ok := equalityMap[sch.Equality]; ok {
				eq = fun
			} else if sch.Equality != "" {
				log.Printf("Warning: equality match function %s not found", sch.Equality)
			}
		}
		for k, vals := range attrs {
			if strings.EqualFold(k, string(f.AttributeDesc())) {
				for _, val := range vals {
					v := string(val)
					if eq(v, string(f.AssertionValue())) {
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
	case message.FilterGreaterOrEqual:
		ord := orderingMap["default"]
		if sch, ok := schemaMap[string(f.AttributeDesc())]; ok {
			if fun, ok := orderingMap[sch.Ordering]; ok {
				ord = fun
			} else if sch.Ordering != "" {
				log.Printf("Warning: ordering match function %s not found", sch.Ordering)
			}
		}
		for k, vals := range attrs {
			if strings.EqualFold(k, string(f.AttributeDesc())) {
				for _, val := range vals {
					if ord(string(val), string(f.AssertionValue())) >= OrderingEqual {
						return true
					}
				}
				// vals not match
				return false
			}
		}
		return false
	case message.FilterLessOrEqual:
		ord := orderingMap["default"]
		if sch, ok := schemaMap[string(f.AttributeDesc())]; ok {
			if fun, ok := orderingMap[sch.Ordering]; ok {
				ord = fun
			} else if sch.Ordering != "" {
				log.Printf("Warning: ordering match function %s not found", sch.Ordering)
			}
		}
		for k, vals := range attrs {
			if strings.EqualFold(k, string(f.AttributeDesc())) {
				for _, val := range vals {
					if ord(string(val), string(f.AssertionValue())) <= OrderingEqual {
						return true
					}
				}
				// vals not match
				return false
			}
		}
		return false
	default:
		// TODO
		return false
	}
}

func handleSearchDSE(w ldap.ResponseWriter, m *ldap.Message) {
	// server specific data
	// https://tools.ietf.org/html/rfc4512#section-5.1
	res := ldap.NewSearchResultEntry("")
	res.AddAttribute("supportedSASLMechanisms")
	res.AddAttribute("supportedLDAPVersion", "3")
	w.Write(res)
	w.Write(ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess))
	log.Printf("[%s]Sent DSE data", m.Client.Addr())
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	if bindDN[m.Client.Numero] == "" {
		w.Write(ldap.NewSearchResultDoneResponse(ldap.LDAPResultInappropriateAuthentication))
		return
	}

	r := m.GetSearchRequest()

	log.Printf("[%s]Search id=%d base=%s filter=%s attrs=%s", m.Client.Addr(), m.MessageID(), r.BaseObject(), r.FilterString(), r.Attributes())
	parts := getParts(string(r.BaseObject()))
	key := strings.Join(parts, ",")
	resp, err := kvc.Get(context.Background(), key+",", clientv3.WithPrefix())
	if err != nil {
		log.Printf("[%s]Failed to search entry %s: %s", m.Client.Addr(), key, err)
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
			log.Printf("[%s]Failed to unmarshal json: %s", m.Client.Addr(), err)
			continue
		}

		if !matchFilter(r.Filter(), value) {
			continue
		}

		// output in order
		keys := make([]string, len(value))
		i := 0
		for k := range value {
			keys[i] = k
			i++
		}
		sort.Strings(keys)
		for _, k := range keys {
			res.AddAttribute(message.AttributeDescription(k), value[k]...)
		}
		w.Write(res)
		count = count + 1
	}
	log.Printf("[%s]Search response id=%d entries=%d", m.Client.Addr(), m.MessageID(), count)
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleAdd(w ldap.ResponseWriter, m *ldap.Message) {
	// requires bind to dn
	if bindDN[m.Client.Numero] == "" {
		log.Printf("[%s]Access denied to add entry by anonymous user",
			m.Client.Addr())
		w.Write(ldap.NewAddResponse(ldap.LDAPResultInappropriateAuthentication))
		return
	}

	// only root dn can add entries
	if bindDN[m.Client.Numero] != rootDN {
		log.Printf("[%s]Access denied to add entry by user %s",
			m.Client.Addr(), bindDN[m.Client.Numero])
		w.Write(ldap.NewAddResponse(ldap.LDAPResultInsufficientAccessRights))
		return
	}

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

	// operational attribuets
	// https://tools.ietf.org/html/rfc4512#section-3.4
	t := time.Now().Format(generalizedTimeFormat)
	attrs["creatorsName"] = []message.AttributeValue{message.AttributeValue(bindDN[m.Client.Numero])}
	attrs["createTimestamp"] = []message.AttributeValue{message.AttributeValue(t)}
	attrs["modifiersName"] = []message.AttributeValue{message.AttributeValue(bindDN[m.Client.Numero])}
	attrs["modifyTimestamp"] = []message.AttributeValue{message.AttributeValue(t)}

	for k, v := range attrs {
		// auto encryption
		if strings.EqualFold(k, "userPassword") {
			for i := range v {
				if !strings.HasPrefix(string(v[i]), "{crypt}") {
					n, err := passwordEncrypt(string(v[i]))
					if err != nil {
						log.Printf("[%s]Failed to encrypt password: %s", m.Client.Addr(), err)
						res := ldap.NewModifyResponse(ldap.LDAPResultOther)
						w.Write(res)
						return
					}
					attrs[k][i] = message.AttributeValue(string(n))
				}
			}
		}
	}

	val, err := json.Marshal(attrs)
	if err != nil {
		log.Printf("[%s]Got error when marshal attributes into json: %s", m.Client.Addr(), err)
		res := ldap.NewAddResponse(ldap.LDAPResultUnavailable)
		w.Write(res)
		return
	}

	txn = txn.Then(clientv3.OpPut(key, string(val)))
	txn = txn.Else(clientv3.OpGet(key))
	resp, err := txn.Commit()

	if err != nil {
		log.Printf("[%s]Got error when add request: %s", m.Client.Addr(), err)
		res := ldap.NewAddResponse(ldap.LDAPResultUnavailable)
		w.Write(res)
	} else {
		if resp.Succeeded {
			// success
			log.Printf("[%s]Add entry: %s", m.Client.Addr(), key)
			res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
			w.Write(res)
		} else {
			if resp.Responses[0].GetResponseRange().GetCount() > 0 {
				// already exists
				log.Printf("[%s]Failed to add entry %s: already exists", m.Client.Addr(), key)
				res := ldap.NewAddResponse(ldap.LDAPResultEntryAlreadyExists)
				w.Write(res)
			} else {
				// parent does not exist
				log.Printf("[%s]Failed to add entry %s: parent does not exist", m.Client.Addr(), key)
				res := ldap.NewAddResponse(ldap.LDAPResultNoSuchObject)
				w.Write(res)
			}
		}
	}
}

func handleDelete(w ldap.ResponseWriter, m *ldap.Message) {
	if bindDN[m.Client.Numero] == "" {
		log.Printf("[%s]Access denied to delete entry by anonymous user",
			m.Client.Addr())
		w.Write(ldap.NewDeleteResponse(ldap.LDAPResultInappropriateAuthentication))
		return
	}

	// only root dn can delete entries
	if bindDN[m.Client.Numero] != rootDN {
		log.Printf("[%s]Access denied to delete entry by user %s",
			m.Client.Addr(), bindDN[m.Client.Numero])
		w.Write(ldap.NewDeleteResponse(ldap.LDAPResultInsufficientAccessRights))
		return
	}

	// https://tools.ietf.org/html/rfc4511#section-4.8
	r := m.GetDeleteRequest()
	parts := getParts(string(r))

	key := strings.Join(parts, ",")
	// TODO: check if children exist
	resp, err := kvc.Delete(context.Background(), key)
	if err != nil {
		log.Printf("[%s]Failed to delete entry %s: %s", m.Client.Addr(), key, err)
		res := ldap.NewDeleteResponse(ldap.LDAPResultOther)
		w.Write(res)
	} else {
		if resp.Deleted > 0 {
			log.Printf("[%s]Entry %s deleted", m.Client.Addr(), key)
			res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
			w.Write(res)
		} else {
			log.Printf("[%s]Failed to delete nonexistent entry %s", m.Client.Addr(), key)
			res := ldap.NewDeleteResponse(ldap.LDAPResultNoSuchObject)
			w.Write(res)
		}
	}
}

func handleAbandon(w ldap.ResponseWriter, m *ldap.Message) {
}

func handleStartTLS(w ldap.ResponseWriter, m *ldap.Message) {
	// https://tools.ietf.org/html/rfc4511#section-4.14
	cert, err := tls.LoadX509KeyPair(host.TLSCert, host.TLSKey)
	if err != nil {
		log.Printf("StartTLS failed when loading x509 keypair: %s", err)
		res := ldap.NewResponse(ldap.LDAPResultUnwillingToPerform)
		w.Write(res)
		return
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ServerName:   "127.0.0.1",
	}
	tlsConn := tls.Server(m.Client.GetConn(), tlsConfig)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	res.SetResponseName(ldap.NoticeOfStartTLS)
	w.Write(res)

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[%s]StartTLS Handshake error %s", m.Client.Addr(), err)
		res.SetResultCode(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	m.Client.SetConn(tlsConn)
	log.Printf("[%s]StartTLS Done", m.Client.Addr())
}

func passwordEncrypt(val string) (string, error) {
	if !strings.HasPrefix(val, "{crypt}") {
		crypt := crypt.SHA512.New()
		n, err := crypt.Generate([]byte(val), []byte{})
		if err != nil {
			return "", err
		}
		return "{crypt}" + string(n), nil
	}
	return val, nil
}

func handleModify(w ldap.ResponseWriter, m *ldap.Message) {
	if bindDN[m.Client.Numero] == "" {
		log.Printf("[%s]Access denied to modify entry by anonymous user",
			m.Client.Addr())
		w.Write(ldap.NewModifyResponse(ldap.LDAPResultInappropriateAuthentication))
		return
	}

	// https://tools.ietf.org/html/rfc4511#section-4.6
	r := m.GetModifyRequest()
	log.Printf("[%s]Handle modify %s", m.Client.Addr(), r.Object())

	// root dn can modify all entries,
	// while others can only modify their own
	if !(bindDN[m.Client.Numero] == rootDN || bindDN[m.Client.Numero] == string(r.Object())) {
		log.Printf("[%s]Access denied to modify entry by user %s",
			m.Client.Addr(), bindDN[m.Client.Numero])
		w.Write(ldap.NewDeleteResponse(ldap.LDAPResultInsufficientAccessRights))
		return
	}

	key := getKey(string(r.Object()))

	// try at most 10 times
	for i := 0; i < 10; i++ {
		resp, err := kvc.Get(context.Background(), key)
		if err != nil {
			log.Printf("[%s]Entry %s not found: %s", m.Client.Addr(), key, err)
			res := ldap.NewModifyResponse(ldap.LDAPResultNoSuchObject)
			w.Write(res)
			return
		}

		before := resp.Kvs[0].Value
		var value map[string][]message.AttributeValue
		err = json.Unmarshal(before, &value)
		if err != nil {
			log.Printf("[%s]Failed to unmarshal json: %s", m.Client.Addr(), err)
			res := ldap.NewModifyResponse(ldap.LDAPResultOther)
			w.Write(res)
			return
		}

		for _, change := range r.Changes() {
			t := string(change.Modification().Type_())
			mod := change.Modification().Vals()
			// auto encrypt for userPassword
			if strings.EqualFold(t, "userPassword") {
				for i := range mod {
					if !strings.HasPrefix(string(mod[i]), "{crypt}") {
						n, err := passwordEncrypt(string(mod[i]))
						if err != nil {
							log.Printf("[%s]Failed to encrypt password: %s", m.Client.Addr(), err)
							res := ldap.NewModifyResponse(ldap.LDAPResultOther)
							w.Write(res)
							return
						}
						mod[i] = message.AttributeValue(string(n))
					}
				}
			}

			switch change.Operation() {
			case ldap.ModifyRequestChangeOperationAdd:
				s := []message.AttributeValue{}
				key := t
				for k := range value {
					if strings.EqualFold(k, t) {
						// found key
						s = value[k]
						key = k
						break
					}
				}
				s = append(s, mod...)
				value[key] = s
			case ldap.ModifyRequestChangeOperationDelete:
				for k := range value {
					if strings.EqualFold(k, t) {
						// found key
						vals := map[string]bool{}
						// add original
						for _, v := range value[k] {
							vals[string(v)] = true
						}
						// remove deleted
						for _, v := range mod {
							delete(vals, string(v))
						}
						// collect
						n := []message.AttributeValue{}
						for k := range vals {
							n = append(n, message.AttributeValue(k))
						}
						if len(n) > 0 {
							value[k] = n
						} else {
							// remove if empty
							delete(value, k)
						}
						break
					}
				}
			case ldap.ModifyRequestChangeOperationReplace:
				key := t
				for k := range value {
					if strings.EqualFold(k, t) {
						// found key
						key = k
						break
					}
				}
				if len(mod) > 0 {
					value[key] = mod
				} else {
					// remove if empty
					delete(value, key)
				}
			}
		}

		// operational attribuets
		// https://tools.ietf.org/html/rfc4512#section-3.4
		t := time.Now().Format(generalizedTimeFormat)
		value["modifiersName"] = []message.AttributeValue{message.AttributeValue(bindDN[m.Client.Numero])}
		value["modifyTimestamp"] = []message.AttributeValue{message.AttributeValue(t)}

		after, err := json.Marshal(value)
		if err != nil {
			log.Printf("[%s]Failed to marshal json: %s", m.Client.Addr(), err)
			res := ldap.NewModifyResponse(ldap.LDAPResultOther)
			w.Write(res)
			return
		}

		// update if untouched
		txn := kvc.Txn(context.Background()).
			If(clientv3.Compare(clientv3.Value(key), "=", string(before))).
			Then(clientv3.OpPut(key, string(after)))
		txnResp, err := txn.Commit()
		if err != nil {
			log.Printf("[%s]Failed to submit txn: %s", m.Client.Addr(), err)
			res := ldap.NewModifyResponse(ldap.LDAPResultOther)
			w.Write(res)
			return
		}

		if txnResp.Succeeded {
			log.Printf("[%s]Entry %s updated from %s to %s", m.Client.Addr(), key, before, after)
			res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
			w.Write(res)
			return
		}

		// fail, retry
	}

	log.Printf("[%s]Entry update conflicted too many times: %s", m.Client.Addr(), key)
	res := ldap.NewModifyResponse(ldap.LDAPResultNoSuchObject)
	w.Write(res)
}

func handlePasswordModify(w ldap.ResponseWriter, m *ldap.Message) {
	if bindDN[m.Client.Numero] == "" {
		w.Write(ldap.NewExtendedResponse(ldap.LDAPResultInappropriateAuthentication))
		return
	}

	// https://tools.ietf.org/html/rfc3062#section-2
	r := m.GetExtendedRequest()

	val := r.RequestValue().Bytes()
	pkt, err := ber.DecodePacketErr(val)
	if err != nil || len(pkt.Children) != 3 {
		res := ldap.NewExtendedResponse(ldap.LDAPResultOther)
		w.Write(res)
	}
	dn := pkt.Children[0].Data.String()
	oldPass := pkt.Children[1].Data.String()
	newPass := pkt.Children[2].Data.String()

	log.Printf("[%s]Handle password modify %s", m.Client.Addr(), dn)

	// root dn can modify all passwords,
	// while others can only modify their own
	if !(bindDN[m.Client.Numero] == rootDN || bindDN[m.Client.Numero] == dn) {
		log.Printf("[%s]Access denied to modify password of %s by user %s",
			m.Client.Addr(), dn, bindDN[m.Client.Numero])
		w.Write(ldap.NewDeleteResponse(ldap.LDAPResultInsufficientAccessRights))
		return
	}

	key := getKey(dn)
	// try at most 10 times
	for i := 0; i < 10; i++ {
		resp, err := kvc.Get(context.Background(), key)
		if err != nil {
			log.Printf("[%s]Entry %s not found: %s", m.Client.Addr(), key, err)
			res := ldap.NewExtendedResponse(ldap.LDAPResultNoSuchObject)
			w.Write(res)
			return
		}

		before := resp.Kvs[0].Value
		var value map[string][]message.AttributeValue
		err = json.Unmarshal(before, &value)
		if err != nil {
			log.Printf("[%s]Failed to unmarshal json: %s", m.Client.Addr(), err)
			res := ldap.NewExtendedResponse(ldap.LDAPResultOther)
			w.Write(res)
			return
		}

		userPassword, ok := value["userPassword"]
		if !ok || len(userPassword) != 1 {
			log.Printf("[%s]Bad password in entry %s", m.Client.Addr(), key)
			res := ldap.NewExtendedResponse(ldap.LDAPResultOther)
			w.Write(res)
			return
		}

		pass := string(userPassword[0])

		correct := true
		if strings.HasPrefix(pass, "{crypt}") {
			pass := strings.TrimPrefix(pass, "{crypt}")
			if crypt.IsHashSupported(pass) {
				// crypt
				crypt := crypt.NewFromHash(pass)
				err := crypt.Verify(pass, []byte(oldPass))
				correct = err == nil
			} else {
				correct = false
			}
		} else {
			// clear text?
			correct = pass == oldPass
		}
		if !correct {
			log.Printf("[%s]Wrong password in entry %s", m.Client.Addr(), key)
			res := ldap.NewExtendedResponse(ldap.LDAPResultInvalidCredentials)
			w.Write(res)
			return
		}

		npass, err := passwordEncrypt(newPass)
		if err != nil {
			log.Printf("[%s]Failed to hash password: %s", m.Client.Addr(), err)
			res := ldap.NewExtendedResponse(ldap.LDAPResultOther)
			w.Write(res)
			return
		}
		value["userPassword"] = []message.AttributeValue{message.AttributeValue(npass)}

		// operational attribuets
		// https://tools.ietf.org/html/rfc4512#section-3.4
		t := time.Now().Format(generalizedTimeFormat)
		value["modifiersName"] = []message.AttributeValue{message.AttributeValue(bindDN[m.Client.Numero])}
		value["modifyTimestamp"] = []message.AttributeValue{message.AttributeValue(t)}

		after, err := json.Marshal(value)
		if err != nil {
			log.Printf("[%s]Failed to marshal json: %s", m.Client.Addr(), err)
			res := ldap.NewExtendedResponse(ldap.LDAPResultOther)
			w.Write(res)
			return
		}

		// update if untouched
		txn := kvc.Txn(context.Background()).
			If(clientv3.Compare(clientv3.Value(key), "=", string(before))).
			Then(clientv3.OpPut(key, string(after)))
		txnResp, err := txn.Commit()
		if err != nil {
			log.Printf("[%s]Failed to submit txn: %s", m.Client.Addr(), err)
			res := ldap.NewExtendedResponse(ldap.LDAPResultOther)
			w.Write(res)
			return
		}

		if txnResp.Succeeded {
			log.Printf("[%s]Entry %s updated from %s to %s", m.Client.Addr(), key, before, after)
			res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
			w.Write(res)
			return
		}

		// fail, retry
	}

	log.Printf("[%s]Entry update conflicted too many times: %s", m.Client.Addr(), key)
	res := ldap.NewExtendedResponse(ldap.LDAPResultNoSuchObject)
	w.Write(res)
}
