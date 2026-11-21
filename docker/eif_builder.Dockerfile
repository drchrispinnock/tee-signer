# nitro-cli in a container, so EIFs can be built on any Docker host (including macOS).
# nitro-cli's bundled kernel blobs determine PCR1, so its version is pinned.
ARG BASE_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:5c38fd85b00ce8c094315d9b71f671f880052314a22bd25f1a027821bf61d9d7
FROM $BASE_IMAGE
ARG NITRO_CLI_VERSION=1.5.3-0.amzn2023
RUN dnf install -y \
      "aws-nitro-enclaves-cli-${NITRO_CLI_VERSION}" \
      "aws-nitro-enclaves-cli-devel-${NITRO_CLI_VERSION}" \
      docker \
    && dnf clean all
ENTRYPOINT ["nitro-cli"]
