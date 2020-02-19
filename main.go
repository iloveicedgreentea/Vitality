package main

import (
	"fmt"
	"log"
	"os"

	awsssm "github.com/PaddleHQ/go-aws-ssm"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/iloveicedgreentea/Vitality/scanner"
	"github.com/aws/aws-sdk-go/service/ssm"

	// "github.com/spf13/viper"

	"github.com/urfave/cli/v2"
)

func init() {

}

func main() {

	var (
		paramStorePath string
		awsRegion      string
		awsProfile     string
		apikey         = ""
	)

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
				Destination: &awsRegion,
			},
			&cli.StringFlag{
				Name:        "awsProfile",
				Value:       "default",
				Aliases:     []string{"pr"},
				Usage:       "AWS Profile - will use default if not provided",
				Destination: &awsProfile,
			},
			// todo? instead of passing multiple -i make it one string and split later
			&cli.StringSliceFlag{
				Name:     "scanItems",
				Usage:    "List of items to scan - urls and/or file paths can be mixed",
				Aliases:  []string{"i"},
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
			// set up aws session to pass region and profile to SSM
			awsSession, err := session.NewSessionWithOptions(session.Options{
				Profile: awsProfile,

				Config: aws.Config{
					Region: aws.String(awsRegion),
				},
			})
			if err != nil {
				log.Fatal(err)
			}

			ssmClient := ssm.New(awsSession)

			fmt.Printf("Getting API key from SSM - %s\n", paramStorePath)

			// Create param store client
			paramstore := awsssm.NewParameterStoreWithClient(ssmClient)

			// grab the secret
			param, err := paramstore.GetParameter(paramStorePath, true)
			if err != nil {
				log.Fatal(err)
			}

			// decode the param
			apikey = param.GetValue()

		} else {
			fmt.Println("Getting API key from environment")
			apikey = os.Getenv("VT_API_KEY")
		}
		
		fmt.Println("Starting VT Scan")
		scanner.Scan(c.StringSlice("scanItems"), apikey)
		return nil
	}

	// Run the app
	err := app.Run(os.Args)

	if err != nil {
		log.Fatal(err)
	}

}
