FROM golang:1.26.7-alpine3.23@sha256:b17af760035fc2f338eed92d448a6c67f2d45438844fc6c60678fa5f99e44b57

RUN apk add --no-cache iproute2 nftables

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV TB_RUN_INTEGRATION=1
ENV TB_COVERAGE_DIR=/artifacts
RUN mkdir -p /artifacts

CMD ["go", "test", "-v", "-count=1", "-covermode=atomic", "-coverpkg=./...", "-coverprofile=/artifacts/coverage.integration.out", "./integration"]
