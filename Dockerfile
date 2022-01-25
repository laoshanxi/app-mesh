FROM laoshanxi/appmesh:build_ubuntu20 AS builder

WORKDIR /workspace

COPY . .

RUN mkdir build; cd build; cmake ..; make; make pack; make test ARG='-V'

FROM ubuntu:20.04

COPY --from=builder /workspace/build/appmesh*.deb /opt/

RUN apt-get update && \
    apt-get install -y /opt/appmesh*.deb && rm -f /opt/appmesh*.deb && \
    apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
    apt-get update && apt install -y docker-ce-cli iputils-ping tini && \
    apt-get remove -y curl apt-transport-https ca-certificates curl gnupg-agent software-properties-common && \
    apt-get clean

EXPOSE 6060

# not enable exec user in container
ENV APPMESH_DisableExecUser=true

CMD ["tini", "--", "/opt/appmesh/script/appmesh-entrypoint.sh"]

# reference:
#   https://blog.csdn.net/alex_yangchuansheng/article/details/106394119?utm_term=linuxsbintini&utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~all~sobaiduweb~default-0-106394119&spm=3001.4430
