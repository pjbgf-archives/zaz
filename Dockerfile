FROM golang:1.12-buster as build

LABEL repository="https://github.com/pjbgf/zaz/"
LABEL maintainer="pjbgf@linux.com"

RUN apt update && apt install git gcc

WORKDIR /go/src/pjbgf/zaz
ADD . /go/src/pjbgf/zaz

ENV GO111MODULE=on

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

RUN go build -o /zaz


FROM alpine 
COPY --from=build /zaz /
CMD ["/zaz"]

