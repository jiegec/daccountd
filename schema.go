package main

// Equality type
type Equality int

// Equality functions
const (
	EqualityIntegerMatch Equality = iota
	EqualityCaseIgnoreIA5Match
	EqualityCaseExactIA5Match
	EqualityCaseExactMatch
)

// Substrings type
type Substrings int

// Substrings functions
const (
	SubstringsUnspecified Substrings = iota
	SubstringsCaseIgnoreIA5SubstringsMatch
)

// Schema for LDAP entries
type Schema struct {
	Oid         string
	Name        string
	Desc        string
	Equality    Equality
	Syntax      string
	Substrings  Substrings
	SingleValue bool
}

// NewSchema creates a new schema
func NewSchema(oid string, name string, desc string, equality Equality, substrings Substrings, syntax string, singleValue bool) Schema {
	return Schema{
		Name:        name,
		Desc:        desc,
		Equality:    equality,
		Substrings:  substrings,
		Syntax:      syntax,
		SingleValue: singleValue,
	}
}

// ClassSchema is schema for LDAP classes
type ClassSchema struct {
	Name string
	Sup  string
	Desc string
	Must []Schema
	May  []Schema
}
