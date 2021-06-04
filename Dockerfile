FROM ubuntu:20.04

ADD ./appmesh*.deb /opt

RUN apt update && \
    apt install -y /opt/appmesh*.deb && \
    apt install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
    apt update && \
    apt install -y docker-ce-cli && rm -f /opt/appmesh*.deb

EXPOSE 6060

ENTRYPOINT ["/opt/appmesh/script/appmesh-entrypoint.sh"]
