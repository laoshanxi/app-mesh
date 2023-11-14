## Build

App Mesh is implemented by modern C++, require g++ version higher than 4.8.5, there are 2 ways to setup App Mesh build environment.

Build host support RHEL, Ubuntu, Debian and Fedora distributions with X86 or ARM architecture.

### Option 1: Setup build environment on local host

The general way build all dependencies on local Linux host, this will build all the dependency libraries and need some time to finish.

```shell
$ git clone --depth=1 https://github.com/laoshanxi/app-mesh.git
$ sudo bash app-mesh/script/openssl_update.sh
$ sudo bash app-mesh/autogen.sh
# clean
$ rm -rf app-mesh dep
```

After environment was setup with above steps, use bellow steps to build App Mesh. `make test ARGS="-V"` is used to run Unit Test after `make`.

```shell
cd app-mesh
mkdir build; cd build; cmake ..; make; make pack; make test ARGS="-V"
```

### Option 2: Build by docker image

The simple way is use docker image `laoshanxi/appmesh:build_centos8` to build App Mesh directly which already have compiler and dependencies installed.

```shell
cd app-mesh
docker run --rm -v $(pwd):$(pwd) -w $(pwd) laoshanxi/appmesh:build_centos8 sh -c "mkdir build;cd build;cmake ..;make;make pack;make test ARGS='-V'"
```

Build a Docker image to compile C++ application is a reliable and easy way to handle third party dependencies, anyone could use this docker image to build package without prepare a C++ environment.

There are different Dockerfile(s) with different compiler version could be selected to generate the Docker image:

- docker/Dockerfile.build_centos8
- docker/Dockerfile.build_ubuntu18
- docker/Dockerfile.build_ubuntu20
- docker/Dockerfile.build_ubuntu22

The Docker image build process is simple with this:

```shell
TAG_NAME=build_ubuntu20
MAGE_NAME=laoshanxi/appmesh:${TAG_NAME}

git clone --depth=1 https://github.com/laoshanxi/app-mesh.git
cd app-mesh

! docker rmi -f ${IMAGE_NAME}
! docker rmi ubuntu:20.04
docker build --no-cache -f docker/Dockerfile.${TAG_NAME} -t ${IMAGE_NAME} .
docker push ${IMAGE_NAME}
```

The public pre-build Docker images can be used to build binary directly:

- laoshanxi/appmesh:build_centos8
- laoshanxi/appmesh:build_ubuntu18
- laoshanxi/appmesh:build_ubuntu20
- laoshanxi/appmesh:build_ubuntu22
- laoshanxi/appmesh:build_ubuntu18_arm64
