package scanner

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

var (
	baseURL = "https://www.virustotal.com/vtapi/v2/"
)

// Structs

// VtScanResponse JSON of the scan response
type VtScanResponse struct {
	//TODO! Make json struct of the return response
	/*
		{
		'permalink': 'https://www.virustotal.com/file/d140c...244ef892e5/analysis/1359112395/',
		'resource': 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556',
		'response_code': 1,
		'scan_id': 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556-1359112395',
		'verbose_msg': 'Scan request successfully queued, come back later for the report',
		'sha256': 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556'
		}
	*/
}

// Send files to VT and scan
// todo: think about splitting this into a function to scan, another to display output
// todo: will make it easier to use scan outputs for other functions like uploading somewhere

// todo! add support for scanType | url or file

// Scan scan a url or file and return the output as json
func Scan(scanType string, paths []string) *VtScanResponse {
	fmt.Println(paths)
	//Todo: send to /file/scan POST
	/*
			curl --request POST \
		--url 'https://www.virustotal.com/vtapi/v2/file/scan' \
		--form 'apikey=<apikey>' \
		--form 'file=@/path/to/file'
	*/
	//todo: check scanType
	// todo! make this concurrent
	for _, path := range paths {
		resp, err := http.PostForm(baseURL, url.Values{"apikey": {"test123"}, "file": {path}})
		if err != nil {
			//todo: handle error
			log.Fatal(err)
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			//todo: handle error
			log.Fatal(err)
		}
		fmt.Println(body)
		//todo: wait for scan to be ready
	}
	// todo: make this return the correct object, which may be a list of VtScanResponse
	return nil
}

// func S3Upload() {

// }

// func Slack() {

// }
