FROM laoshanxi/appmesh:build_ubuntu22 AS compile_stage
RUN cd /opt && git clone https://github.com/laoshanxi/app-mesh.git && \
	cd app-mesh && mkdir build && cd build && cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl .. && make -j"$(nproc)" && make pack && ls

FROM python:3.13-slim
ARG AM_UID="482"
ARG AM_GID="482"
# not enable exec user in container
ENV APPMESH_BaseConfig_DisableExecUser=true
# not only listen 127.0.0.1
ENV APPMESH_REST_RestListenAddress=0.0.0.0
COPY --from=compile_stage /opt/app-mesh/build/appmesh*.deb .
RUN ls && apt-get update && \
	apt-get install -y tini && \
	apt-get install -y ./appmesh*.deb && \
	pip3 install --break-system-packages --no-cache-dir appmesh && \
	rm -f ./appmesh*.deb && apt-get clean && rm -rf /var/lib/apt/lists/* && \
	rm -rf /opt/appmesh/apps/ping.yaml && rm -rf /opt/appmesh/apps/backup.yaml && \
	groupadd -r -g $AM_GID appmesh && useradd -m -r -u $AM_UID -g appmesh appmesh && \
	ln -s /opt/appmesh/script/appmesh-entrypoint.sh / && \
	touch /opt/appmesh/appmesh.pid && \
	chown -R appmesh:appmesh /opt/appmesh/ && \
	. /usr/bin/appc -v && /opt/appmesh/bin/appsvc -v
EXPOSE 6060
USER appmesh
WORKDIR /
ENTRYPOINT ["tini", "--", "/appmesh-entrypoint.sh"]

##################################################################################
# docker container, accept parameters as bellow format:
#  1. Run docker container and register a long running application
#     docker run -d laoshanxi/appmesh ping github.com
#  2. Run docker container and excute an external cmd
#     docker run -d laoshanxi/appmesh appc ls
##################################################################################
# reference:
# https://blog.csdn.net/alex_yangchuansheng/article/details/106394119?utm_term=linuxsbintini&utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~all~sobaiduweb~default-0-106394119&spm=3001.4430
# https://github.com/grafana/grafana-docker/blob/master/Dockerfile
# https://pythonspeed.com/articles/smaller-python-docker-images/
