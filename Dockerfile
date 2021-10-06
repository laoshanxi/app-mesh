FROM ubuntu:20.04

ADD ./appmesh*.deb /opt

RUN apt update &&
    apt install -y /opt/appmesh*.deb && rm -f /opt/appmesh*.deb &&
    apt install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common &&
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - &&
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" &&
    apt update && apt install -y docker-ce-cli iputils-ping vim tini &&
    apt-get clean

EXPOSE 6060

ENTRYPOINT ["tini", "--", "/opt/appmesh/script/appmesh-entrypoint.sh"]

# reference:
#   https://blog.csdn.net/alex_yangchuansheng/article/details/106394119?utm_term=linuxsbintini&utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~all~sobaiduweb~default-0-106394119&spm=3001.4430
