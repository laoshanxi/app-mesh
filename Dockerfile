FROM laoshanxi/appmesh:build_ubuntu24 AS COMPILE_STAGE
RUN cd /opt && git clone https://github.com/laoshanxi/app-mesh.git && \
	cd app-mesh && mkdir build && cd build && cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl .. && make -j4 && make pack && ls


FROM python:3.12-slim AS PYTHON_STAGE
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir appmesh


FROM ubuntu:24.04
ARG AM_UID="482"
ARG AM_GID="482"
# not enable exec user in container
ENV APPMESH_DisableExecUser=true
# not only listen 127.0.0.1
ENV APPMESH_REST_RestListenAddress=0.0.0.0
COPY --from=PYTHON_STAGE /opt/venv /opt/venv
COPY --from=COMPILE_STAGE /opt/app-mesh/build/appmesh*.deb .
ENV PATH="$PATH:/opt/venv/bin"
RUN apt-get update && \
	apt-get install -y tini && \
	apt-get install -y ./appmesh*.deb && \
	rm -f ./appmesh*.deb && apt-get clean && rm -rf /var/lib/apt/lists/* && \
	rm -rf /opt/appmesh/apps/ping.json && rm -rf /opt/appmesh/apps/backup.yaml && \
	groupadd -r -g $AM_GID appmesh && useradd -m -r -u $AM_UID -g appmesh appmesh && \
	ln -s /opt/appmesh/script/appmesh-entrypoint.sh / && \
	touch /var/run/appmesh.pid && \
	chown -R appmesh:appmesh /opt/appmesh/ /var/run/appmesh.pid && \
	. /usr/bin/appc -v && /opt/appmesh/bin/appsvc -v
EXPOSE 6060
USER appmesh
WORKDIR /
ENTRYPOINT ["tini", "--", "/appmesh-entrypoint.sh"]

##################################################################################
# docker container, accept parameters as bellow format:
#  1. Run docker container and register a long running application
#     docker run -d laoshanxi/appmesh ping www.baidu.com
#  2. Run docker container and excute an external cmd
#     docker run -d laoshanxi/appmesh appc ls
##################################################################################
# reference:
# https://blog.csdn.net/alex_yangchuansheng/article/details/106394119?utm_term=linuxsbintini&utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~all~sobaiduweb~default-0-106394119&spm=3001.4430
# https://github.com/grafana/grafana-docker/blob/master/Dockerfile
# https://pythonspeed.com/articles/smaller-python-docker-images/
