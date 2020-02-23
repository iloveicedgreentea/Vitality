package logger

import (
	"fmt"
	"os"
)

// Debug will print a message if DEBUG_FLAG is true
func Debug(line string) {
	if os.Getenv("DEBUG_FLAG") == "true" {
		fmt.Println(line)
	}
}
