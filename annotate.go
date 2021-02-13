package main

import (
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// code is taken from https://github.com/go-ldap/ldap/blob/master/ldap.go
// and https://github.com/go-ldap/ldap/blob/master/control.go

const (
	// ControlTypePaging - https://www.ietf.org/rfc/rfc2696.txt
	ControlTypePaging = "1.2.840.113556.1.4.319"
	// ControlTypeBeheraPasswordPolicy - https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
	ControlTypeBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1"
	// ControlTypeVChuPasswordMustChange - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlTypeVChuPasswordMustChange = "2.16.840.1.113730.3.4.4"
	// ControlTypeVChuPasswordWarning - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlTypeVChuPasswordWarning = "2.16.840.1.113730.3.4.5"
	// ControlTypeManageDsaIT - https://tools.ietf.org/html/rfc3296
	ControlTypeManageDsaIT = "2.16.840.1.113730.3.4.2"

	// ControlTypeMicrosoftNotification - https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
	ControlTypeMicrosoftNotification = "1.2.840.113556.1.4.528"
	// ControlTypeMicrosoftShowDeleted - https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
	ControlTypeMicrosoftShowDeleted = "1.2.840.113556.1.4.417"
)

// ControlTypeMap maps controls to text descriptions
var ControlTypeMap = map[string]string{
	ControlTypePaging:                "Paging",
	ControlTypeBeheraPasswordPolicy:  "Password Policy - Behera Draft",
	ControlTypeManageDsaIT:           "Manage DSA IT",
	ControlTypeMicrosoftNotification: "Change Notification - Microsoft",
	ControlTypeMicrosoftShowDeleted:  "Show Deleted Objects - Microsoft",
}

func annotateMessage(packet *ber.Packet) {
	packet.Description = "LDAP Message"
	packet.Children[0].Description = "Message ID"

	application := uint8(packet.Children[1].Tag)
	packet.Children[1].Description = ldap.ApplicationMap[application]

	switch application {
	case ldap.ApplicationBindRequest:
		annotateBindRequest(packet.Children[1])
	}
}

func annotateBindRequest(packet *ber.Packet) error {
	// BindRequest
	// version INTEGER (1 .. 127)
	packet.Children[0].Description = "Version"
	// name LDAPDN
	packet.Children[1].Description = "Name"
	// authentication AuthenticationChoice
	packet.Children[2].Description = "Authentication"
	return nil
}
