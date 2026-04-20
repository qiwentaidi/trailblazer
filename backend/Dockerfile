# Build
FROM docker.1ms.run/library/golang:latest AS build-env
#RUN apk add build-base
WORKDIR /app
COPY . /app

RUN go env -w GOPROXY=https://goproxy.cn,direct && go mod download
RUN go build

# Release
FROM docker.1ms.run/library/debian:bookworm
#RUN apk cache clean && apk upgrade --no-cache \
#    && apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /app/trailblazer /usr/local/bin/
# 拷贝 config 目录
COPY --from=build-env /app/config.yaml /config.yaml

ENTRYPOINT ["trailblazer"]
