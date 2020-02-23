FROM golang:1.13.8-buster as builder

WORKDIR /go/src/app
COPY . /go/src/app

RUN go get -d -v ./...

# Build for linux and mac
RUN go build -o /go/bin/vt

FROM gcr.io/distroless/base
COPY --from=builder /go/bin/vt /bin/vt