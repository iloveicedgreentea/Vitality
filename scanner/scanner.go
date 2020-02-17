package scanner

import (
	"fmt"
)

// Send files to VT and scan
// todo: think about splitting this into a function to scan, another to display output
// todo: will make it easier to use scan outputs for other functions like uploading somewhere
func Scan(paths []string) {
	fmt.Println(paths)
}

// func S3Upload() {

// }

// func Slack() {

// }
