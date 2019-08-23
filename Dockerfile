FROM centos

ADD ./appmanager-1.2-1.x86_64.rpm /opt

RUN yum install /opt/appmanager-1.2-1.x86_64.rpm -y

EXPOSE 6060

ENTRYPOINT ["/bin/sh","-c" ,"/opt/appmanager/script/appmg_watchdog.sh"]