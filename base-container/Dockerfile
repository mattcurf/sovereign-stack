FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 AS bootstrap-tools
ENV SOURCE_DATE_EPOCH=1789027200
COPY sources.list /etc/apt/sources.list
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends mmdebstrap=1.5.7-1+deb13u1
COPY bootstrap.sh /usr/local/bin/bootstrap

FROM bootstrap-tools AS bootstrap
RUN /usr/local/bin/bootstrap

FROM scratch
COPY --from=bootstrap /rootfs/ /
ENV LANG=C.UTF-8 HOME=/tmp
USER 65532:65532
WORKDIR /tmp
CMD ["/bin/sh"]
