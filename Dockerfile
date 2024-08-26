FROM alpine:3
RUN apk add --no-cache jq bash
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
