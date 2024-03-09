FROM debian:bookworm-20240211-slim AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && \
	apt-get -y dist-upgrade

FROM base AS build-env
RUN apt-get -y install \
	build-essential \
	gcc-multilib \
	autoconf \
	automake \
	libtool \
	libnl-3-dev \
	libnl-route-3-dev \
	libnuma-dev \
	libudev-dev \
	libxdp-dev \
	clang \
	uuid-dev \
	pkg-config \
	python-is-python3

FROM build-env AS build-libfabric
WORKDIR /src
ADD https://github.com/ofiwg/libfabric/releases/download/v1.20.1/libfabric-1.20.1.tar.bz2 .
RUN tar --no-same-owner -jxvf libfabric-1.20.1.tar.bz2 \
	&& ln -s libfabric-1.20.1 libfabric
WORKDIR /src/libfabric
RUN autoreconf
RUN ./configure
RUN make -j $(nproc)
# test
RUN make -j $(nproc) check
RUN util/fi_info
# install
RUN make install DESTDIR=/stage

FROM build-libfabric AS build-uet
WORKDIR /src/uet
ADD . .
RUN make
RUN make xdp

FROM base AS runtime
RUN apt-get -y install \
	libnuma1 \
	libuuid1 \
	libxdp1 \
	libnl-3-200 \
	libnl-route-3-200
COPY --from=build-libfabric /stage /
RUN ldconfig
RUN fi_info
COPY --from=build-uet /src/uet/uet /usr/bin/
COPY --from=build-uet /src/uet/uet_xdp /usr/bin/
