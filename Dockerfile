FROM ubuntu:20.04

ADD ./appmesh*.deb /opt

RUN apt update && apt install docker.io -y && apt install /opt/appmesh*.deb -y

EXPOSE 6060

ENTRYPOINT ["/opt/appmesh/script/appmesh-entrypoint.sh"]
