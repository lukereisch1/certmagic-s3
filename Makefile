
.PHONY: build run

build:
	xcaddy build --with github.com/caddy-dns/cloudflare --with github.com/lukereisch1/certmagic-s3=.

run:
	./caddy run --config ./Caddyfile