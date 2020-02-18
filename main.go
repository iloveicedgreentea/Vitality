package main

import (
	"fmt"
	"log"
	"os"

	awsssm "github.com/PaddleHQ/go-aws-ssm"
	"github.com/iloveicedgreentea/Vitality/scanner"

	// "github.com/spf13/viper"

	"github.com/urfave/cli/v2"
)

func init() {

}

func main() {

	// test := viper.New()
	// fmt.Println(test)

	// Param store path
	var paramStorePath string
	var apikey = ""

	app := &cli.App{
		Name:    "Vitality",
		Version: "v0.0.1",
		Authors: []*cli.Author{
			&cli.Author{
				Name: "Ilan Ponimansky",
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "parameterStorePath",
				Value:       "",
				Aliases:     []string{"p"},
				Usage:       "Path to AWS Parameter Store value. If not empty, use parameter store to lookup VT API key",
				Destination: &paramStorePath,
			},
			&cli.StringFlag{
				Name:        "awsRegion",
				Value:       "us-east-1",
				Aliases:     []string{"r"},
				Usage:       "Region to use - defaults to us-east-1",
				Destination: &paramStorePath,
			},

			&cli.StringSliceFlag{
				Name:     "filePaths",
				Usage:    "List of file paths to scan",
				Aliases:  []string{"f"},
				Required: true,
			},
		},
		// Commands: []*cli.Command{
		// },
	}

	// Define how to run the scanner in the context of the cli
	app.Action = func(c *cli.Context) error {
		// if paramStorePath is empty, it was not supplied
		if paramStorePath != "" {
			fmt.Printf("Grabbing API key from %s\n", paramStorePath)

			// Create param store client
			paramstore, err := awsssm.NewParameterStore()
			if err != nil {
				return err
			}

			// grab the secret
			param, err := paramstore.GetParameter(paramStorePath, true)
			if err != nil {
				return err
			}

			// decode the param
			apikey = param.GetValue()
			//todo! debug
			fmt.Println(apikey)

		} else {
			fmt.Println("Grabbing API key from environment")
			apikey = os.Getenv("VT_API_KEY")
		}
		scanner.Scan("file", c.StringSlice("filePaths"), apikey)
		return nil
	}

	// Run the app
	err := app.Run(os.Args)

	if err != nil {
		log.Fatal(err)
	}

}
