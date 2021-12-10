FROM laoshanxi/appmesh:build_centos7 AS builder

WORKDIR /workspace

COPY . .

RUN mkdir build;cd build;cmake ..;make;make pack;make test ARG='-V'

FROM ubuntu:20.04

COPY --from=builder /workspace/build/appmesh_2.0.1_amd64.deb /opt/appmesh_2.0.1_amd64.deb

RUN apt update && \
    apt install -y /opt/appmesh*.deb && rm -f /opt/appmesh*.deb && \
    apt install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
    apt update && apt install -y docker-ce-cli iputils-ping vim tini &&  \
    apt-get clean

EXPOSE 6060

ENTRYPOINT ["tini", "--", "/opt/appmesh/script/appmesh-entrypoint.sh"]

# reference:
#   https://blog.csdn.net/alex_yangchuansheng/article/details/106394119?utm_term=linuxsbintini&utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~all~sobaiduweb~default-0-106394119&spm=3001.4430
