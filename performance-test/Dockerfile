FROM tailscale/tailscale:v1.98.8@sha256:d54b2e6a9c09f0e5ec52e82b9ad4af3d446b54a7c08075e92f11c39dd410105f

RUN apk add --no-cache nginx coreutils
COPY performance-test/nginx.conf /etc/nginx/http.d/default.conf.template
COPY performance-test/entrypoint.sh /usr/local/bin/performance-test-entrypoint
RUN chmod 0755 /usr/local/bin/performance-test-entrypoint

ENTRYPOINT ["/usr/local/bin/performance-test-entrypoint"]
