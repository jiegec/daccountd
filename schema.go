package main

import (
	"embed"
	"log"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// Schema is a schema for LDAP
type Schema struct {
	Oid                string
	Link               string
	Name               string
	Desc               string
	Sup                string
	Auxiliary          bool
	Must               []string
	May                []string
	Equality           string
	Ordering           string
	Syntax             string
	SingleValue        bool
	NoUserModification bool
	Usage              string
}

// SchemaFile is struct for schema.yml
type SchemaFile struct {
	Oid []struct {
		Name string
		Oid  string
	}
	Schemas []Schema
}

//go:embed schema.yml
var schemaContent string
var schema SchemaFile
var schemaMap map[string]Schema

// avoid error
type useEmbed embed.FS

const generalizedTimeFormat string = "20060102150405-0700"

func init() {
	err := yaml.Unmarshal([]byte(schemaContent), &schema)
	if err != nil {
		log.Fatalf("Error in schema.yml: %v", err)
	}

	schemaMap = make(map[string]Schema)
	for _, v := range schema.Schemas {
		schemaMap[v.Name] = v
	}
}

type equalityFunc func(string, string) bool

var equalityMap = map[string]equalityFunc{
	"integerMatch": func(s1, s2 string) bool { return s1 == s2 },
	"generalizedTimeMatch": func(s1, s2 string) bool {
		t1, _ := time.Parse(generalizedTimeFormat, s1)
		t2, _ := time.Parse(generalizedTimeFormat, s2)
		return t1 == t2
	},
	"caseIgnoreIA5Match": func(s1, s2 string) bool {
		return strings.EqualFold(s1, s2)
	},
}
