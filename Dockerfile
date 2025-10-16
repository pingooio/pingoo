# By using the FROM --platform= pattern we can reuse some steps between platforms.
# For now we can't use cross-compilation for the build step as not all our build tools support
# cross-compilation.
# https://docs.docker.com/build/building/multi-platform
# https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/

####################################################################################################
## Build Javascript projects
####################################################################################################
FROM --platform=$BUILDPLATFORM node:lts AS builder_js

RUN apt update && apt upgrade -y && \
    apt install -y libimage-exiftool-perl make

WORKDIR /pingoo
COPY . ./

# build captcha
WORKDIR /pingoo/captcha
RUN make exif
RUN make clean
RUN make install_ci
RUN make build


####################################################################################################
## Build pingoo
####################################################################################################
FROM rust:alpine AS pingoo_build

RUN apk add --no-cache --no-progress \
    git make bash curl wget zip gnupg coreutils gcc g++ zstd binutils ca-certificates upx \
    lld mold musl musl-dev cmake clang clang-dev openssl openssl-dev zstd
RUN update-ca-certificates

WORKDIR /pingoo
COPY . ./
RUN make clean

COPY --from=builder_js /pingoo/captcha/dist/ /pingoo/captcha/dist/
RUN make build


####################################################################################################
## This stage is used to get the correct files to the final image
## We use Debian instead of the traditional Ubuntu because their root certificates (ca-certificates)
## are certainly more secure.
####################################################################################################
FROM --platform=$BUILDPLATFORM debian:13-slim AS builder_files

# appuser
ENV USER=pingoo
ENV UID=10001

# mailcap is used for content type (MIME type) detection
RUN apt update && apt upgrade -y && \
    apt install -y mailcap ca-certificates adduser wget
RUN update-ca-certificates

ENV TZ="UTC"
RUN echo "${TZ}" > /etc/timezone

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

# Use the /etc/pingoo folder for configuration
RUN mkdir -p /etc/pingoo
RUN mkdir -p /etc/pingoo/rules
COPY ./assets/pingoo.yml /etc/pingoo/pingoo.yml
RUN chown -R $USER:$USER /etc/pingoo

# Use the /usr/share/pingoo folder for static data.
# reference: https://en.wikipedia.org/wiki/Filesystem_Hierarchy_Standard
WORKDIR /usr/share/pingoo
RUN wget https://downloads.pingoo.io/geoip.mmdb.zst
RUN chown -R $USER:$USER /usr/share/pingoo


####################################################################################################
## Final image
####################################################################################################
FROM scratch

# /etc/nsswitch.conf and resolv.conf may be used by some DNS resolvers
# /etc/mime.types may be used to detect the MIME type of files
# /etc/passwd \
# /etc/group \
COPY --from=builder_files \
    /etc/nsswitch.conf \
    /etc/mime.types \
    /etc/timezone \
    /etc/resolv.conf \
    /etc/

COPY --from=builder_files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder_files /usr/share/zoneinfo /usr/share/zoneinfo

# --chown=pingoo:pingoo
COPY --from=builder_files /etc/pingoo /etc/pingoo
COPY --from=builder_files /usr/share/pingoo /usr/share/pingoo
COPY ./assets/www /var/www

# Copy our build
COPY --from=pingoo_build /pingoo/dist/pingoo /bin/pingoo

# Use an unprivileged user
# USER pingoo:pingoo

# The final working directory
WORKDIR /home/pingoo

ENTRYPOINT ["/bin/pingoo"]

EXPOSE 80 443
