package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	baseURL = "https://www.virustotal.com/vtapi/v2/"
	// custom http client to have timeouts
	httpClient = &http.Client{
		Timeout: time.Second * 10,
	}
)

// VtScanResponse JSON of the scan response
type vtScanResponse struct {
	Permalink    string `json:"permalink"`
	Resource     string `json:"resource"`
	ResponseCode int    `json:"response_code"`
	ScanID       string `json:"scan_id"`
	VerboseMsg   string `json:"verbose_msg"`
	Sha256       string `json:"sha256"`
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
			1: queued
			-2: ?? docs are wrong
	*/
}

// struct of each scanner in vtResultResponse.scans
type vtScan struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version"`
	Result   string `json:"result"`
	Update   string `json:"update"`
	/*
		'detected': true,
		'version': '2010-05-14.01',
		'result': 'Trojan.Generic.3611249',
		'update': '20100514'
	*/
}

// struct of the report
type vtResultResponse struct {
	ResponseCode int               `json:"response_code"`
	VerboseMsg   string            `json:"verbose_msg"`
	Resource     string            `json:"resource"`
	ScanID       string            `json:"scan_id"`
	Md5          string            `json:"md5"`
	Sha1         string            `json:"sha1"`
	Sha256       string            `json:"sha256"`
	ScanDate     string            `json:"scan_date"`
	Permalink    string            `json:"permalink"`
	Positives    int               `json:"positives"`
	Total        int               `json:"total"`
	Scans        map[string]vtScan `json:"scans"`

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

func init() {
	if os.Getenv("DEBUG_FLAG") == "true" {
		log.SetLevel(log.DebugLevel)
		log.SetReportCaller(true)
	} else {
		log.SetLevel(log.WarnLevel)
	}
}

// Scan a url or file and return the output as json
func Scan(items []string, apiKey string) error {
	// Check if the API key is empty
	if apiKey == "" {
		log.Debug(apiKey)
		log.Fatal("Invalid API Key")
	}

	log.Debug("Starting Scan function")

	// create channel to hold the response
	scanResultChan := make(chan vtScanResponse, len(items))
	defer close(scanResultChan)

	// loop over the items to scan and async start scan
	for _, val := range items {
		log.Debug("Starting new startScan function")
		go startScan(val, apiKey, scanResultChan)
	}

	// block until done
	//<-scanResultChan

	// create a iterable
	log.Debug(len(items))
	result := make([]vtScanResponse, len(items))
	for val := range result {
		// pull values out of the channel
		result[val] = <-scanResultChan
		log.Debug(result[val].Permalink)
		//todo! get output of channel and process if needed, or it should be processed by another function via the channel
		// if result[i].ResponseCode == 0 etc

	}

	log.Debug("Done inserting values")
	log.Debug("Asking for reports")
	err := getScanResults(result)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

// do a scan on each url and store in a channel
func startScan(item string, apiKey string, channel chan vtScanResponse) {
	var data vtScanResponse
	//check if file or url
	var fileFlag = true
	var re = regexp.MustCompile(`(?m)https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)`)
	var matcher = item

	if re.Match([]byte(matcher)) {
		log.Debug("item is a url")
		fileFlag = false
	}

	if fileFlag {
		log.Debug("item is a file")
		// open the file
		file, err := os.Open(item)
		if err != nil {
			log.Fatal(err)
		}

		// check if file is larger than 32MB
		fileInfo, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		// 32 MB rounded down
		if fileInfo.Size() > 32000000 {
			log.Fatal("File is greater than 32MB")
		}
		log.Debug("File size is ok")
		defer file.Close()

		// store request body in this buffer
		var requestBody bytes.Buffer

		// create a multipart writer to create the request
		multiPartWriter := multipart.NewWriter(&requestBody)
		fileWriter, err := multiPartWriter.CreateFormField("file")
		if err != nil {
			log.Debug(err)
		}

		// copy the file to the file writer
		_, err = io.Copy(fileWriter, file)
		if err != nil {
			log.Debug(err)
		}

		// add the API key to the form
		fieldWriter, err := multiPartWriter.CreateFormField("apikey")
		if err != nil {
			log.Debug(err)
		}
		_, err = fieldWriter.Write([]byte(apiKey))
		if err != nil {
			log.Debug(err)
		}

		// close multipart writer
		multiPartWriter.Close()

		// Create the api url
		scanURL := fmt.Sprintf("%s%s", baseURL, "file/scan")
		log.Debug(scanURL)

		// create a custom request to send
		request, err := http.NewRequest("POST", scanURL, &requestBody)
		if err != nil {
			log.Debug(err)
		}

		// Set content-type header to multipart/form-data
		request.Header.Set("Content-Type", multiPartWriter.FormDataContentType())

		resp, err := httpClient.Do(request)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		//todo! handle this rate limit better, retry after wait
		// check if rate limited
		if resp.StatusCode == 204 {
			log.Fatal("Client was rate limited")
		}

		decoder := json.NewDecoder(resp.Body)

		// store the json in data
		err = decoder.Decode(&data)
		if err != nil {
			log.Debug(data)
			log.Fatal(err)
		}

		channel <- data
	} else {

		formData := url.Values{
			"apikey": {apiKey},
			"url":    {item},
		}

		log.Debug("Starting URL scan")
		// todo! implement url scanning

		// Create the api url
		scanURL := fmt.Sprintf("%s%s", baseURL, "url/scan")
		log.Debug(scanURL)

		// send Post with  x-www-form-urlencoded header
		resp, err := httpClient.PostForm(scanURL, formData)

		defer resp.Body.Close()
		//todo! handle this rate limit better, retry after wait
		// check if rate limited
		if resp.StatusCode == 204 {
			log.Fatal("Client was rate limited")
		}

		decoder := json.NewDecoder(resp.Body)

		// store the json in data
		err = decoder.Decode(&data)
		if err != nil {
			log.Debug(data)
			log.Fatal(err)
		}

		channel <- data

	}

}

//todo! get scan results
func getScanResults(results []vtScanResponse) error {
	// todo: function to ask for results
	// todo: logic to retry and wait + x sec each time
	/*
		curl --request GET \
			--url 'https://www.virustotal.com/vtapi/v2/file/report?apikey=<apikey>&resource=<resource>'
	*/
	fmt.Println("Results")
	return nil

}

// func S3Upload() {

// }

// func Slack() {

// }
