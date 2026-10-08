ARG BASE_IMAGE=sovereign-stack/base-container:local
FROM node:24.21.0-trixie-slim@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66 AS static
# Official npm distribution plus complete patched upstream dependency packages.
ADD --checksum=sha256:9f58bff01604cb1b14008fef14dceb14d836a49225e45c6c2e37de3be3e707f0 https://registry.npmjs.org/npm/-/npm-11.19.1.tgz /tmp/npm.tgz
ADD --checksum=sha256:67bb5a1b4d4a8ff497d845a0b891ffe6b7233aea2202641315cec88d0fff15eb https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.11.tgz /tmp/brace-expansion.tgz
ADD --checksum=sha256:e18191aac9c0ff43dac7fe9b10b7041a22d07addb7b66a6e8ac14a52a5b69b74 https://registry.npmjs.org/undici/-/undici-6.28.1.tgz /tmp/undici.tgz
RUN rm -rf /usr/local/lib/node_modules/npm \
    && mkdir -p /usr/local/lib/node_modules/npm \
    && tar -xzf /tmp/npm.tgz --strip-components=1 -C /usr/local/lib/node_modules/npm \
    && for name in brace-expansion undici; do \
        rm -rf "/usr/local/lib/node_modules/npm/node_modules/$name"; \
        mkdir -p "/usr/local/lib/node_modules/npm/node_modules/$name"; \
        tar -xzf "/tmp/$name.tgz" --strip-components=1 -C "/usr/local/lib/node_modules/npm/node_modules/$name"; \
    done \
    && rm /tmp/npm.tgz /tmp/brace-expansion.tgz /tmp/undici.tgz \
    && test "$(node -p "require('/usr/local/lib/node_modules/npm/node_modules/brace-expansion/package.json').version")" = 5.0.11 \
    && test "$(node -p "require('/usr/local/lib/node_modules/npm/node_modules/undici/package.json').version")" = 6.28.1 \
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
    && apt-get install -y --no-install-recommends nginx=1.26.3-3+deb13u9 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=static /src/dist/ /srv/www/
COPY --from=static /evidence/ /usr/share/sovereign-stack/nginx/
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGQUIT
CMD ["/usr/sbin/nginx", "-g", "daemon off;"]
