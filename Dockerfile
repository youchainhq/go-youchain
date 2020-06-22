FROM golang:1.13 as builder

ADD . /go-youchain
RUN cd /go-youchain && export GOPROXY=https://goproxy.cn/ && make build

FROM frolvlad/alpine-glibc:latest
RUN set -ex \
  && apk update && apk add tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo 'Asia/Shanghai' >/etc/timezone
COPY --from=builder /go-youchain/output/you /bin/you

EXPOSE 7283 8283 8284 9283 9284
ENTRYPOINT ["/bin/you"]
