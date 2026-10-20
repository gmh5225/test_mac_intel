ARG UBUNTU_BASE
ARG PYTHON_BASE
FROM ${UBUNTU_BASE} AS bwrap
RUN apt-get update -qq && cd /tmp && apt-get download bubblewrap=0.6.1-1ubuntu0.3
FROM ${PYTHON_BASE}
COPY --from=bwrap /tmp/bubblewrap_*.deb /tmp/bubblewrap.deb
RUN apt-get update -qq && apt-get install -y --no-install-recommends socat libcap2 binutils gcc g++ libssl-dev bzip2 xz-utils zstd lz4 brotli && dpkg -i /tmp/bubblewrap.deb && rm /tmp/bubblewrap.deb && rm -rf /var/lib/apt/lists/*
RUN python3 --version && dpkg-query -W -f='${Version}' bubblewrap && bwrap --version
RUN apt-get update -qq && apt-get install -y --no-install-recommends xvfb xclip xauth x11-utils && dpkg-query -W -f='${binary:Package}\t${Version}\n' > /owned-package-versions.tsv && rm -rf /var/lib/apt/lists/*
