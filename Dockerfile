FROM cgr.dev/chainguard/static:latest
ARG TARGETARCH
COPY ./dist/xipher-cli_linux_${TARGETARCH}*/xipher /
ENV GODEBUG=madvdontneed=1
USER 65532:65532
ENTRYPOINT ["/xipher"]
