module github.com/iloveicedgreentea/Vitality

go 1.14

require (
	github.com/PaddleHQ/go-aws-ssm v0.4.0
	github.com/aws/aws-sdk-go v1.16.24
	github.com/sirupsen/logrus v1.2.0
	github.com/urfave/cli/v2 v2.1.1
	golang.org/x/net v0.0.0-20190522155817-f3200d17e092 // indirect
)

replace scanner => ./scanner
