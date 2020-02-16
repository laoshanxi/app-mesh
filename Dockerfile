FROM ubuntu:xenial

ADD ./appmanager*.deb /opt

RUN apt install /opt/appmanager*.deb -y

EXPOSE 6060

ENTRYPOINT ["/opt/appmanager/script/appmgr-entrypoint.sh"]
