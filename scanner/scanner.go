package scanner

import (
	"fmt"
	"net/http"
	"net/url"
)

var (
	baseURL = "https://www.virustotal.com/vtapi/v2/"
)

// Structs
type vtResponse struct {
}

// Send files to VT and scan
// todo: think about splitting this into a function to scan, another to display output
// todo: will make it easier to use scan outputs for other functions like uploading somewhere


// todo! add support for scanType | url or file
func Scan(scanType string, paths []string) {
	fmt.Println(paths)
	//Todo: send to /file/scan POST
	/*
		curl --request POST \ 
	--url 'https://www.virustotal.com/vtapi/v2/file/scan' \
	--form 'apikey=<apikey>' \
	--form 'file=@/path/to/file'
	*/
	//todo: check scanType
	// todo: for path in paths:
	resp, err := http.PostForm(baseURL, url.Values{"apikey": {"test123"}, "file": {path} })
	//todo: wait for scan to be ready
}

// func S3Upload() {

// }

// func Slack() {

// }
