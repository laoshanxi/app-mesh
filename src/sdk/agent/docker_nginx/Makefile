DOCKER_IMG_NAME=nginx:mainline-alpine
CONTAINER_NAME=docker_proxy
NGINX_PORT=6058

# SDK: https://docs.docker.com/engine/api/sdk/
# Sample: https://stackoverflow.com/questions/39848796/allow-nginx-to-read-docker-sock

all: clean
#	srw-rw---- 1 root docker 0 Aug  12 09:31 /var/run/docker.sock
	chmod 666 /var/run/docker.sock
#   srw-rw-rw- 1 root docker 0 Aug  12 09:31 /var/run/docker.sock
	docker run -d --name ${CONTAINER_NAME} -u root -p ${NGINX_PORT}:80 -v $(shell pwd)/nginx.conf:/etc/nginx/conf.d/default.conf -v /var/run/docker.sock:/var/run/docker.sock ${DOCKER_IMG_NAME}

clean:
	- docker rm -f ${CONTAINER_NAME}

test:
	curl http://127.0.0.1:${NGINX_PORT}/containers/json
