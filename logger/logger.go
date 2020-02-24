package logger

import (
	"fmt"
	"os"
	"strings"
)

// Debug will print a message if DEBUG_FLAG is true
func Debug(items ...string) {
	if os.Getenv("DEBUG_FLAG") == "true" {
		fmt.Printf("%s\n", strings.Join(items, ", "))
	}
}
