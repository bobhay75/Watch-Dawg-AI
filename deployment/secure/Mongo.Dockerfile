# The upstream server/shell remain pinned; unused helper code is removed.
FROM mongo:8.0@sha256:bdc216e9d5a6ec2cfdac789b5832fdab64cd32055f59885cae918a92de63c361
# Upgrade only the reported Ubuntu main packages using signed HTTPS metadata.
# Skip unrelated universe/multiverse/backports indexes and the MongoDB package
# repository so the pinned server stays unchanged.
RUN set -eu; \
    printf '%s\n' \
        'Types: deb' \
        'URIs: https://archive.ubuntu.com/ubuntu' \
        'Suites: noble noble-updates' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
        '' \
        'Types: deb' \
        'URIs: https://security.ubuntu.com/ubuntu' \
        'Suites: noble-security' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
        > /tmp/watchdawg-ubuntu.sources; \
    set -- -o Dir::Etc::sourcelist=/tmp/watchdawg-ubuntu.sources \
        -o Dir::Etc::sourceparts=- \
        -o Acquire::https::Timeout=30 -o Acquire::Retries=2; \
    apt-get "$@" -o APT::Update::Error-Mode=any update; \
    DEBIAN_FRONTEND=noninteractive apt-get "$@" install -y --no-install-recommends \
        --only-upgrade libc-bin libc6 perl-base; \
    for package in libc-bin libc6; do \
        dpkg --compare-versions "$(dpkg-query -W -f='${Version}' "$package")" \
            ge '2.39-0ubuntu8.12'; \
    done; \
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' perl-base)" \
        ge '5.38.2-3.2ubuntu0.7'; \
    rm -f /tmp/watchdawg-ubuntu.sources; \
    rm -rf /var/lib/apt/lists/*
# No production volume is mounted during this build. These are image files.
# Do not replace this with deletion/pruning of database or evidence paths.
RUN rm -f /usr/local/bin/gosu /usr/local/bin/docker-entrypoint.sh \
      /usr/bin/bsondump /usr/bin/mongodump /usr/bin/mongoexport \
      /usr/bin/mongofiles /usr/bin/mongoimport /usr/bin/mongorestore \
      /usr/bin/mongostat /usr/bin/mongotop \
    && rm -rf /opt/js-yaml
# Root-only init scripts and automatic chown are intentionally unavailable.
USER 999:999
ENTRYPOINT []
CMD ["mongod", "--bind_ip_all"]
