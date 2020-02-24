# Vitality
A CLI interface for VirusTotal written in Go

Usage:
```text
vt [global options] 

[global options]
   --parameterStorePath value, -p value  Path to AWS Parameter Store value. If not empty, use parameter store to lookup VT API key
   --awsRegion value, -r value           Region to use - defaults to us-east-1 (default: "us-east-1")
   --awsProfile value, --pr value        AWS Profile - will use default if not provided (default: "default")
   --scanItems value, -i value           List of items to scan - urls and/or file paths can be mixed
   --help, -h                            show help (default: false)
   --version, -v                         print the version (default: false)
```

## Features

* AWS Parameter Store support for API keys
* Supports both URL and File scans (32 MB limit)

(coming soon®)
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

## Testing
Set `DEBUG_FLAG` to `true` to enable lots of debug output.

Unit tests coming soon®

