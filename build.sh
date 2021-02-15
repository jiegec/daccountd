#!/bin/sh
go build -o daccountd
export CGO_ENABLED=0
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o daccountd-windows-amd64
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o daccountd-darwin-amd64
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o daccountd-linux-amd64
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o daccountd-linux-arm64
GOOS=linux GOARCH=ppc64le go build -ldflags="-s -w" -o daccountd-linux-ppc64le
GOOS=linux GOARCH=mipsle go build -ldflags="-s -w" -o daccountd-linux-mipsle
