FROM ubuntu:xenial

ADD ./appmesh*.deb /opt

RUN apt install /opt/appmesh*.deb -y

EXPOSE 6060

ENTRYPOINT ["/opt/appmesh/script/appmgr-entrypoint.sh"]
