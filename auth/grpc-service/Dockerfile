FROM golang:alpine AS builder

RUN apk --no-cache add make
COPY . /app
RUN make -C /app/grpc-service/cmd/server

FROM alpine:latest

COPY --from=builder /app/grpc-service/cmd/server/server /app/server
CMD ["/app/server"]