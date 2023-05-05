FROM laoshanxi/appmesh:build_ubuntu AS COMPILE_STAGE
RUN cd /opt && git clone https://github.com/laoshanxi/app-mesh.git && \
	cd app-mesh && mkdir build && cd build && cmake .. && make -j4 && make pack && ls


FROM ubuntu:latest AS PYTHON_STAGE
RUN apt-get update && \
	apt-get install -y python3 python3-pip && \
	python3 -m pip install appmesh


FROM ubuntu:latest
ARG AM_UID="482"
ARG AM_GID="482"
# not enable exec user in container
ENV APPMESH_DisableExecUser=true
COPY --from=PYTHON_STAGE /usr/local/lib/python3.10/dist-packages/ /usr/local/lib/python3.10/dist-packages/
COPY --from=COMPILE_STAGE /opt/app-mesh/build/appmesh*.deb .
RUN apt-get update && \
	apt-get install -y python3 iputils-ping tini && \
	apt-get install -y ./appmesh*.deb && rm -f ./appmesh*.deb && apt-get clean && \
	groupadd -r -g $AM_GID appmesh && useradd -m -r -u $AM_UID -g appmesh appmesh && \
	ln -s /opt/appmesh/script/appmesh-entrypoint.sh / && \
	touch /var/run/appmesh.pid && \
	chown -R appmesh:appmesh /opt/appmesh/ /var/run/appmesh.pid
EXPOSE 6060
USER appmesh
WORKDIR /
ENTRYPOINT ["tini", "--", "/appmesh-entrypoint.sh"]

# reference:
# https://blog.csdn.net/alex_yangchuansheng/article/details/106394119?utm_term=linuxsbintini&utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~all~sobaiduweb~default-0-106394119&spm=3001.4430
# https://github.com/grafana/grafana-docker/blob/master/Dockerfile
# https://pythonspeed.com/articles/smaller-python-docker-images/
