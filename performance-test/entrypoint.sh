#!/bin/sh
set -eu

test_port="${PORT:-8080}"
sed "s/__PORT__/${test_port}/g" /etc/nginx/http.d/default.conf.template > /etc/nginx/http.d/default.conf
truncate -s 16G /tmp/tailbridge-performance-payload.bin
nginx
exec /usr/local/bin/containerboot
