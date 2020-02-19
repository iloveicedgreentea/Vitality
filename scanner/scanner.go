package scanner

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sync"
)

var (
	baseURL = "https://www.virustotal.com/vtapi/v2/"
)

// VtScanResponse JSON of the scan response
type vtScanResponse struct {
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
// struct of each scanner in vtResultResponse.scans
type vtScan struct {
	Detected bool `json:"detected"` 
	Version string `json:"version"`
	Result string `json:"result"`
	Update string `json:"update"`
	/*
	'detected': true, 
	'version': '2010-05-14.01', 
	'result': 'Trojan.Generic.3611249', 
	'update': '20100514'
	*/
}
// struct of the report
type vtResultResponse struct {
	ResponseCode int `json:"response_code"`
	VerboseMsg string `json:"verbose_msg"`
	Resource string `json:"resource"`
	ScanID string `json:"scan_id"`
	Md5 string `json:"md5"`
	Sha1 string `json:"sha1"`
	Sha256 string `json:"sha256"`
	ScanDate string `json:"scan_date"`
	Permalink string `json:"permalink"`
	Positives int `json:"positives"`
	Total int `json:"total"`
	Scans map[string]vtScan `json:"scans"`

	/*
		{
		'response_code': 1,
		'verbose_msg': 'Scan finished, scan information embedded in this object',
		'resource': '99017f6eebbac24f351415dd410d522d',
		'scan_id': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724',
		'md5': '99017f6eebbac24f351415dd410d522d',
		'sha1': '4d1740485713a2ab3a4f5822a01f645fe8387f92',
		'sha256': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c',
		'scan_date': '2010-05-15 03:38:44',
		'permalink': 'https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/',
		'positives': 40,
		'total': 40,
		'scans': {
			'nProtect': {
				'detected': true, 
				'version': '2010-05-14.01', 
				'result': 'Trojan.Generic.3611249', 
				'update': '20100514'
			},
			'CAT-QuickHeal': {
				'detected': true, 
				'version': '10.00', 
				'result': 'Trojan.VB.acgy', 
				'update': '20100514'
			},
			'McAfee': {
				'detected': true, 
				'version': '5.400.0.1158', 
				'result': 'Generic.dx!rkx', 
				'update': '20100515'
			},
			'TheHacker': {
				'detected': true, 
				'version': '6.5.2.0.280', 
				'result': 'Trojan/VB.gen', 
				'update': '20100514'
			},   
			'VirusBuster': {
				'detected': true,
				'version': '5.0.27.0',
				'result': 'Trojan.VB.JFDE',
				'update': '20100514'
			}
		}
		}
*/
}

func startScan(item string, apiKey string) *vtScanResponse {
	// responseData, err := httpCall
	// response := vtScanResponse{responseData}
	// return &response 
	// form data to send to VT

	formData := url.Values{
		"apikey": {apiKey}, 
		"file": {item},
	}

	// todo! make custom http client with short timeout
	resp, err := http.PostForm(baseURL, formData)
	//todo! handle rate limits (they send 204 instead of 429)
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


	// todo: make this return the correct object, which may be a list of VtScanResponse
	return nil
}

// Scan a url or file and return the output as json
func Scan(items []string, apiKey string) error {
	//todo: nice to have - check if file size is under 32MB limit

	// Check if the API key is empty
	if apiKey == "" {
		log.Fatal("Invalid API Key")
	}

	//
	// Start the scan
	//
	
	// create a wait group
	var wg sync.WaitGroup

	// loop over the items to scan
	for _, val := range items {
		// increment wait group
		wg.Add(1)
		// async function to scan items
		go func(item string, apikey string) {
			defer wg.Done()
			// todo! this needs to store the data and get retrieved later somehow
			startScan(item, apiKey)
		}(val, apiKey)
	}

	// wait for calls to finish
	wg.Wait()
	//todo: wait for scan to be ready, can wait X seconds or minutes to recheck

	//
	// Check results
	//


	fmt.Println(items)
	return nil
	
	//Todo: send to /file/scan POST
	/*
			curl --request POST \
		--url 'https://www.virustotal.com/vtapi/v2/file/scan' \
		--form 'apikey=<apikey>' \
		--form 'file=@/path/to/file'
	*/
}

// func S3Upload() {

// }

// func Slack() {

// }
