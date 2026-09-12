ARG BASE_IMAGE=sovereign-stack/base-container:local
FROM node:24.21.0-trixie-slim@sha256:6950b66b4c0cb0151ce89fa75074673850763d096b044f422c6729b588dd4956 AS static
# Official npm distribution; replace the complete old tree, not individual dependencies.
ADD --checksum=sha256:9f58bff01604cb1b14008fef14dceb14d836a49225e45c6c2e37de3be3e707f0 https://registry.npmjs.org/npm/-/npm-11.19.1.tgz /tmp/npm.tgz
RUN rm -rf /usr/local/lib/node_modules/npm \
    && mkdir -p /usr/local/lib/node_modules/npm \
    && tar -xzf /tmp/npm.tgz --strip-components=1 -C /usr/local/lib/node_modules/npm \
    && rm /tmp/npm.tgz \
    && test "$(npm --version)" = 11.19.1
WORKDIR /src
COPY package.json package-lock.json build.mjs ./
COPY src/ src/
COPY evidence.sh /usr/local/bin/evidence
RUN npm ci --ignore-scripts --no-audit --no-fund && npm run build \
    && /usr/local/bin/evidence

FROM ${BASE_IMAGE}
USER 0:0
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx=1.26.3-3+deb13u7 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=static /src/dist/ /srv/www/
COPY --from=static /evidence/ /usr/share/sovereign-stack/nginx/
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGQUIT
CMD ["/usr/sbin/nginx", "-g", "daemon off;"]
