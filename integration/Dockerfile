FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc

RUN apk add --no-cache iproute2 nftables

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV TB_RUN_INTEGRATION=1
ENV TB_COVERAGE_DIR=/artifacts
RUN mkdir -p /artifacts

CMD ["go", "test", "-v", "-count=1", "-covermode=atomic", "-coverpkg=./...", "-coverprofile=/artifacts/coverage.integration.out", "./integration"]
