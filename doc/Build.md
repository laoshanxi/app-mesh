## Build

App Mesh was implemented by modern C++ and require g++ version higher than 4.8.5, there are 2 ways to setup App Mesh build environment.

### Option 1: Setup build environment on local host (support Debian and Fedora distribution)
The general way build all dependencies on local Linux host, this will build all the dependencies and need some time to finish.
```shell
$ git clone --depth=1 https://github.com/laoshanxi/app-mesh.git
$ sudo sh app-mesh/script/openssl_update.sh
$ sudo sh app-mesh/autogen.sh
# The above process will create 'dep' directory, this dir can be deleted
```

After environment was setup with above steps, use bellow steps to build App Mesh.
```shell
$ cd app-mesh
$ mkdir build; cd build; cmake ..; make; make pack;
```

### Option 2: Build from docker image
The simple way is use docker container which already have compiler and dependencies, pull image `docker.pkg.github.com/laoshanxi/app-mesh/centos7_build` for the build docker image and use bellow steps to build App Mesh directly.
```shell
$ cd app-mesh
$ docker run --rm -v $(pwd):$(pwd) -w $(pwd) docker.pkg.github.com/laoshanxi/app-mesh/centos7_build sh -c "mkdir build;cd build;cmake ..;make;make pack"
```

BTW, This docker image was built with bellow steps
```shell
$ DATE_STR=$(date "+%Y%m%d")
$ CONTAINER_NAME=centos7_${DATE_STR}
$ IMANGE_NAME=appmesh_build_centos7
$ BASE_IMAGE_NAME=centos/ruby-24-centos7
# for ubuntu, BASE_IMAGE_NAME can be ubuntu:16.04

$ git clone --depth=1 https://github.com/laoshanxi/app-mesh.git
$ cd app-mesh
$ docker rm -f ${CONTAINER_NAME} || true
$ docker run --name ${CONTAINER_NAME} -u root --net=host -v $(pwd):$(pwd) -w $(pwd) ${BASE_IMAGE_NAME} sh -c "sh script/openssl_update.sh; sh autogen.sh"
$ docker rmi -f ${IMANGE_NAME} || true
$ docker commit ${CONTAINER_NAME} ${IMANGE_NAME}
$ docker rm -f ${CONTAINER_NAME} || true
```
