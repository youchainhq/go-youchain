FROM frolvlad/alpine-glibc:latest
RUN set -ex \
  && apk update && apk add tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo 'Asia/Shanghai' >/etc/timezone
COPY ./output/you-linux-amd64 /bin/you

EXPOSE 7283 8283 8284 9283 9284
ENTRYPOINT ["/bin/you"]
