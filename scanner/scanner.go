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
	Permalink string `json:"permalink"`
	Resource string `json:"resource"`
	ResponseCode int `json:"response_code"`
	ScanID string `json:"scan_id"`
	VerboseMsg string `json:"verbose_msg"`
	Sha256 string `json:"sha256"`
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
	/*
	response_code: 
		0: not in DB
		1: ready to get retrieved
		-2: queued
	*/
}

// Scan scan a url or file and return the output as json
func Scan(items []string, apiKey string) *VtScanResponse {

	//todo: nice to have - check if file size is under 32MB limit

	fmt.Println(items)
	return nil
	
	//Todo: send to /file/scan POST
	/*
			curl --request POST \
		--url 'https://www.virustotal.com/vtapi/v2/file/scan' \
		--form 'apikey=<apikey>' \
		--form 'file=@/path/to/file'
	*/
	// todo! add support for  url or file, use regex per item

	// todo! make this concurrent
	for _, item := range items {

		// form data to send to VT
		formData := url.Values{
			"apikey": {apiKey}, 
			"file": {item},
		}
		// todo! make custom http client with short timeout
		resp, err := http.PostForm(baseURL, formData)
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
