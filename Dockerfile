FROM docker.io/jasonish/suricata:7.0.16 AS prod
RUN dnf -y update && \
    dnf -y install nss nss-softokn lua lua-json lua-socket && \
    dnf -y clean all && \
    rm -rf /var/cache/dnf/*
COPY configs/suricata.yaml /etc/suricata/suricata.yaml
COPY configs/http_custom.lua /etc/suricata/http_custom.lua

FROM prod AS dev
COPY tests /tests
WORKDIR /tests