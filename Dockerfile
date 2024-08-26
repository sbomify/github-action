FROM alpine:3
RUN apk add --no-cache jq bash curl
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
