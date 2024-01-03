FROM scratch
ARG TARGETARCH
COPY ./dist/xipher_linux_${TARGETARCH}*/ /
WORKDIR /data
ENTRYPOINT ["/xipher"]