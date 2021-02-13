package main

import (
	"log"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func dumpPacket(packet *ber.Packet, indent int) {
	log.Printf("%sId=%+v Val=%+v Desc=%s", strings.Repeat(" ", indent), packet.Identifier, packet.Value, packet.Description)
	for i := range packet.Children {
		dumpPacket(packet.Children[i], indent+2)
	}
}

// Conn is a LDAP connection
type Conn struct {
	c net.Conn
}

func handleLdapConnection(c net.Conn) {
	log.Printf("Handle LDAP connection from %s", c.RemoteAddr().String())
	conn := Conn{
		c: c,
	}
	defer conn.c.Close()
	for {
		packet, err := ber.ReadPacket(conn.c)
		if err != nil {
			log.Print("Failed to read packet: ", err)
			return
		}
		annotateMessage(packet)
		dumpPacket(packet, 0)
		conn.handleMessage(packet)
	}
}

// LdapServer starts ldap server on 1389
func LdapServer() {
	l, err := net.Listen("tcp", ":1389")
	if err != nil {
		log.Fatal("Failed to listen", err)
		return
	}
	log.Printf("Listening LDAP on :1389")

	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal("Failed to accept", err)
			return
		}
		go handleLdapConnection(c)
	}
}
