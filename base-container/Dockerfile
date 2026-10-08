FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS bootstrap-tools
ENV SOURCE_DATE_EPOCH=1791360000
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
