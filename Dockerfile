FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /ots-server ./cmd/server

FROM alpine:3.21
RUN addgroup -S ots && adduser -S ots -G ots
COPY --from=build /ots-server /usr/local/bin/ots-server
USER ots
EXPOSE 14788
ENTRYPOINT ["ots-server"]
