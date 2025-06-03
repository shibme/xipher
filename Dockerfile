FROM scratch
ARG TARGETARCH
COPY ./dist/xipher-cli_linux_${TARGETARCH}*/xipher /
ENV GODEBUG=madvdontneed=1
ENTRYPOINT ["/xipher"]