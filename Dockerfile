FROM busybox:latest AS dir

RUN mkdir -pm 400 /ngx-oauth2_conf

FROM alpine:latest AS builder

COPY src/ /src/

RUN apk update && apk add --no-cache go \
    && cd /src/exec && cd ngx-oauth2/ \
    && CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /usr/bin/ngx-oauth2

FROM scratch AS app

COPY --from=dir /ngx-oauth2_conf /ngx-oauth2_conf
COPY --from=builder /usr/bin/ngx-oauth2 /ngx-oauth2

ENTRYPOINT [ "/ngx-oauth2" ]
CMD [ "/ngx-oauth2_conf/ngx-oauth2.yml" ]