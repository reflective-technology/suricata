FROM docker.io/jasonish/suricata:8.0.7 AS prod
# Do not `dnf -y update` dpdk: a newer dpdk SONAME breaks the precompiled
# suricata binary in the base image, so it stays version-locked.
RUN dnf -y install --nobest --setopt=install_weak_deps=False python3-dnf-plugin-versionlock && \
    dnf -y versionlock dpdk dpdk-devel && \
    dnf -y update --nobest --setopt=install_weak_deps=False && \
    dnf -y clean all && \
    rm -rf /var/cache/dnf/*
COPY configs/suricata.yaml /etc/suricata/suricata.yaml
COPY configs/rules/ /etc/suricata/rules/

FROM prod AS dev
COPY tests /tests
WORKDIR /tests
