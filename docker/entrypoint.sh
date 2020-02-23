#!/bin/bash

# Build for linux and mac
GOOS=darwin GOARCH=amd64 go build -o /go/bin/vt