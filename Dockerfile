FROM laoshanxi/appmesh:build_ubuntu AS builder

WORKDIR /workspace

COPY . .

RUN mkdir build; cd build; cmake ..; make -j2; make pack; make test ARG='-V'

FROM ubuntu:latest

COPY --from=builder /workspace/build/appmesh*.deb /opt/

ARG AM_UID="482"
ARG AM_GID="482"

# not enable exec user in container
ENV APPMESH_DisableExecUser=true \
    DOCKER_RUNNING=true

RUN apt-get update && \
    apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
    apt-get update && apt install -y docker-ce-cli && \
    apt-get install -y python3 iputils-ping tini && \
    apt-get install -y /opt/appmesh*.deb && rm -f /opt/appmesh*.deb && apt-get clean && \
    groupadd -r -g $AM_GID appmesh && useradd -r -u $AM_UID -g appmesh appmesh && \
    echo "" > /var/run/appmesh.pid && \
    chown -R appmesh:appmesh /opt/appmesh/ /var/run/appmesh.pid

EXPOSE 6060

USER appmesh
WORKDIR /
CMD ["tini", "--", "/opt/appmesh/script/appmesh-entrypoint.sh"]

# reference:
# https://blog.csdn.net/alex_yangchuansheng/article/details/106394119?utm_term=linuxsbintini&utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~all~sobaiduweb~default-0-106394119&spm=3001.4430
# https://github.com/grafana/grafana-docker/blob/master/Dockerfile
