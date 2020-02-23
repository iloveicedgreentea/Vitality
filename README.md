# Vitality
A CLI interface for VirusTotal written in Go

## Features

* AWS Parameter Store support for API keys

(coming soon)
* Automated scanning of arbitrary file list
* Slack integration
* Upload reports to S3

## Building

### Build in Docker (Recommended)
```
make build
```

### Build locally:
```
make build_system
```

Both will output a binary into `./bin/vt`



