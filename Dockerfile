FROM ubuntu:latest as stage
COPY src/sdk/python/requirements.txt .
RUN apt-get update && \
	apt-get install -y python3 python3-pip && \
	python3 -m pip install --exists-action=w --no-cache-dir --requirement ./requirements.txt


FROM ubuntu:latest
ARG AM_UID="482"
ARG AM_GID="482"
# not enable exec user in container
ENV APPMESH_DisableExecUser=true
RUN apt-get update && \
	apt-get install -y python3 iputils-ping tini && \
	apt-get install -y wget && \
	wget --output-document=appmesh.deb https://github.com/laoshanxi/app-mesh/releases/download/2.1.1/appmesh_2.1.1_gcc_11_glibc_2.35_x86_64.deb && \
	apt-get install -y ./appmesh.deb && rm -f ./appmesh.deb && apt-get remove -y wget && apt-get clean && \
	groupadd -r -g $AM_GID appmesh && useradd -r -u $AM_UID -g appmesh appmesh && \
	echo "" > /var/run/appmesh.pid && \
	chown -R appmesh:appmesh /opt/appmesh/ /var/run/appmesh.pid
COPY --from=stage /usr/local/lib/python3.10/dist-packages/ /usr/local/lib/python3.10/dist-packages/
EXPOSE 6060
USER appmesh
WORKDIR /
CMD ["tini", "--", "/opt/appmesh/script/appmesh-entrypoint.sh"]

# reference:
# https://blog.csdn.net/alex_yangchuansheng/article/details/106394119?utm_term=linuxsbintini&utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~all~sobaiduweb~default-0-106394119&spm=3001.4430
# https://github.com/grafana/grafana-docker/blob/master/Dockerfile
# https://pythonspeed.com/articles/smaller-python-docker-images/
