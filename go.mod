module github.com/iloveicedgreentea/Vitality

go 1.13

require (
	github.com/PaddleHQ/go-aws-ssm v0.4.0
	github.com/aws/aws-sdk-go v1.16.24
	github.com/spf13/viper v1.6.2
	github.com/urfave/cli/v2 v2.1.1
)

replace scanner => ./scanner

replace logger => ./logger
