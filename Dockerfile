# autho web UI in a container. The image holds only the compiled binary: no
# vault, no keys, no config. Your vault lives in the /data volume.
#
#   docker run --rm -it -v autho-data:/data niradler/autho init
#   docker run -d --name autho -p 127.0.0.1:8061:8061 -v autho-data:/data niradler/autho
#
# Publish the port on 127.0.0.1 only: the server answers requests addressed to
# localhost and nothing else, and the vault should not be reachable from the LAN.

# The build always runs natively and cross-compiles for the target arch.
FROM --platform=$BUILDPLATFORM oven/bun:1.4.2 AS build
ARG TARGETARCH
WORKDIR /src
# .dockerignore keeps vaults, .env files, node_modules and build output out of the context.
COPY . .
# The UI build runs here, so it needs this machine's native packages (Vite's bundler).
RUN bun install --frozen-lockfile --ignore-scripts && bun run build:ui
# The binary embeds the TUI's native library, so reinstall for the target CPU.
RUN CPU=$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64) \
 && TARGET=$([ "$TARGETARCH" = "arm64" ] && echo bun-linux-arm64 || echo bun-linux-x64-baseline) \
 && bun install --frozen-lockfile --ignore-scripts --os=linux --cpu="$CPU" \
 && bun build ./apps/cli/src/index.ts --compile --minify --no-compile-autoload-dotenv --no-compile-autoload-bunfig \
      --target="$TARGET" --outfile=/out/autho \
 && mkdir -p /out/data

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="autho" \
      org.opencontainers.image.description="Local-first secret manager: web UI and CLI" \
      org.opencontainers.image.source="https://github.com/niradler/autho" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/autho /usr/local/bin/autho
COPY --from=build --chown=nonroot:nonroot /out/data /data
# AUTHO_WEB_CONTAINER lets the server bind 0.0.0.0 inside the container (it still
# only answers Host: localhost). There is no OS keychain here, so it is off.
ENV AUTHO_HOME=/data \
    AUTHO_DISABLE_OS_SECRETS=1 \
    AUTHO_WEB_CONTAINER=1
USER nonroot
VOLUME ["/data"]
EXPOSE 8061
ENTRYPOINT ["/usr/local/bin/autho"]
CMD ["web", "serve", "--host", "0.0.0.0"]
