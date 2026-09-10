# The e2e's in-network toolbox: this library's cpp_driver built for Linux
# next to the `nats` CLI. Needed because the auth-callout SERVICE has to be a
# NATS client that shells out to cpp_driver per request (`nats reply
# --command`), and the host-built driver (macOS locally, glibc on CI) cannot
# run inside the nats-box container. Build context: the repo root.
FROM alpine:3.20 AS build
RUN apk add -q build-base cmake linux-headers git
COPY . /src
RUN cmake -S /src -B /b -DCMAKE_BUILD_TYPE=Release -DJWT_BUILD_TESTS=OFF -DJWT_BUILD_DRIVER=ON >/dev/null \
 && cmake --build /b --target cpp_driver -j >/dev/null

FROM natsio/nats-box:0.14.5
# nats-box is alpine but ships no C++ runtime (measured: exit 127 from the
# loader — libstdc++.so.6 / libgcc_s.so.1 not found)
RUN apk add -q libstdc++
COPY --from=build /b/cpp_driver /usr/local/bin/cpp_driver
