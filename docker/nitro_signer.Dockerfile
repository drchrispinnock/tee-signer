# Pinned by digest (multi-arch index: amd64 + arm64) so builds are reproducible.
# Update deliberately: a new digest changes PCR0.
ARG BASE_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:2@sha256:f1e677d4e1674fdf860331805f0af4a516c5524e3ba0a5663cee49a96df1f648
ARG RUST_VERSION=1.95.0

FROM $BASE_IMAGE AS builder

ARG RELEASE
ARG RUST_VERSION
# Used by BuildKit to clamp file timestamps (see scripts/build-eif.sh).
ARG SOURCE_DATE_EPOCH

RUN yum install -y \
    gcc \
    git \
    tar \
    make

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION}

COPY . /tee-signer
RUN source $HOME/.cargo/env && cd tee-signer && cargo build --locked ${RELEASE:+--release} --bin nitro_signer_app

RUN mkdir -p /rootfs
WORKDIR /rootfs

RUN [ ! -z "$RELEASE" ] && TGT="release" || TGT="debug"; \
    BINS="/tee-signer/target/$TGT/nitro_signer_app" && \
    for bin in $BINS; do \
    ldd "$bin" | grep -Eo "/.*lib.*/[^ ]+" | \
    while read path; do \
    mkdir -p "./$(dirname $path)"; \
    cp -fL "$path" "./$path"; \
    done \
    done && \
    for bin in $BINS; do cp "$bin" .; done

RUN mkdir -p ./etc/pki/tls/certs/ && cp -f /etc/pki/tls/certs/* ./etc/pki/tls/certs/
RUN find ./

FROM scratch

COPY --from=builder /rootfs /

ARG PROXY_PORT
ARG PROXY_CID
ARG LISTEN_PORT

ENV PROXY_PORT=${PROXY_PORT}
ENV PROXY_CID=${PROXY_CID}
ENV LISTEN_PORT=${LISTEN_PORT}

CMD ["/nitro_signer_app"]
