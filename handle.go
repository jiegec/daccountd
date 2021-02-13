package main

import (
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func (conn *Conn) handleMessage(packet *ber.Packet) {
	application := uint8(packet.Children[1].Tag)

	switch application {
	case ldap.ApplicationBindRequest:
		conn.handleBindRequest(packet)
	}
}

func (conn *Conn) handleBindRequest(packet *ber.Packet) {
	// rfc4511 section 4.2.1
	bind := packet.Children[1]

	// If the server does not support the specified version,
	// it MUST respond with a BindResponse where the resultCode is set to protocolError.
	if bind.Children[0].Value != 3 {
		// TODO
	}

	name := bind.Children[1].Value
	log.Printf("Bind with name=%s", name)

	resp := ber.NewSequence("LDAP Message")
	resp.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, packet.Children[1].Value, "Message ID"))
	inner := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "Bind Response")
	resp.AppendChild(inner)

	dumpPacket(resp, 0)
}
