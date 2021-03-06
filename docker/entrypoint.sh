#!/bin/bash

# store cache locally for 7x build speedup since we don't have docker cache available
export GOCACHE="${PWD}/.cache"
go mod tidy
# Build for mac
GOOS=darwin GOARCH=amd64 go build -o "${PWD}/bin/vt"
