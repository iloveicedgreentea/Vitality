package main

import (
	// TODO: Add boto

	"log"
	"os"

	"github.com/iloveicedgreentea/Vitality/scanner"

	"github.com/urfave/cli/v2"
)

func main() {

	// Param store path
	var paramStorePath string
	// Initial container for all files to scan
	var filePaths string
	// slice to store the split paths
	var filePathList []string

	app := &cli.App{
		Flags: []cli.Flag{
			// TODO: aws param store support
			&cli.StringFlag{
				Name:        "parameterStorePath",
				Value:       "",
				Aliases:     []string{"p"},
				Usage:       "Path to AWS Parameter Store value. If not empty, use parameter store to lookup VT API key",
				Destination: &paramStorePath,
			},
			&cli.PathFlag{
				Name:        "filePaths",
				Usage:       "List of file paths to scan",
				Aliases:     []string{"f"},
				Destination: &filePaths,
				//todo: need to split this by space into []string
			},
		},
		Commands: []*cli.Command{
			//todo: add default command of scanning, run a func
		},
	}

	err := app.Run(os.Args)

	//todo: testing, doesn't actually do anything
	scanner.Scan(filePathList)

	if err != nil {
		log.Fatal(err)
	}
}
