FROM scratch
ARG TARGETARCH
COPY ./dist/xipher-cli_linux_${TARGETARCH}*/ /
ENTRYPOINT ["/xipher"]