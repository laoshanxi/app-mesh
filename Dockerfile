FROM ubuntu:xenial

ADD ./appmesh*.deb /opt

RUN apt update && apt install /opt/appmesh*.deb -y

EXPOSE 6060

ENTRYPOINT ["/opt/appmesh/script/appmesh-entrypoint.sh"]
