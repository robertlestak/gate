FROM golang:1.19 as builder

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o /bin/gate cmd/gate/*.go

FROM gcr.io/distroless/base-debian10 as app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /bin/gate /bin/gate

ENTRYPOINT ["/bin/gate"]