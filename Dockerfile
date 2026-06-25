FROM docker.io/jasonish/suricata:7.0.15 AS prod
# Do not `dnf -y update` here: it pulls whatever dpdk is newest in the
# AlmaLinux/EPEL repos at build time, which can bump the dpdk SONAME (e.g.
# 25 -> 26) and break the precompiled suricata binary in the base image,
# which is linked against the dpdk version it shipped with.
RUN dnf -y install nss nss-softokn lua lua-json lua-socket && \
    dnf -y clean all && \
    rm -rf /var/cache/dnf/*
COPY configs/suricata.yaml /etc/suricata/suricata.yaml
COPY configs/http_custom.lua /etc/suricata/http_custom.lua

FROM prod AS dev
COPY tests /tests
WORKDIR /tests