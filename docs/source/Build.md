## Build

App Mesh is implemented by modern C++, require g++ version higher than 4.8.5, there are 2 ways to setup App Mesh build environment.

Build host support RHEL, Ubuntu, Debian and Fedora distributions with X86 or ARM architecture.

### Option 1: Setup build environment on local host

The general way build all dependencies on local Linux host, this will build all the dependency libraries and need some time to finish.
```shell
$ git clone --depth=1 https://github.com/laoshanxi/app-mesh.git
$ sudo sh app-mesh/script/openssl_update.sh
$ sudo sh app-mesh/autogen.sh
# clean
$ rm -rf app-mesh dep
```

After environment was setup with above steps, use bellow steps to build App Mesh. `make test ARGS="-V"` is used to run Unit Test after `make`.
```shell
$ cd app-mesh
$ mkdir build; cd build; cmake ..; make; make pack; make test ARGS="-V"
```

### Option 2: Build by docker image

The simple way is use docker container `laoshanxi/appmesh:build_centos7` to build App Mesh directly which already have compiler and dependencies installed.

```shell
$ cd app-mesh
$ docker run --rm -v $(pwd):$(pwd) -w $(pwd) laoshanxi/appmesh:build_centos7 sh -c "mkdir build;cd build;cmake ..;make;make pack;make test ARGS='-V'"
```

docker image `laoshanxi/appmesh:build_centos7` was built with bellow steps:
https://github.com/laoshanxi/app-mesh/issues/97


All available build docker images (each one use the default g++ version):

- laoshanxi/appmesh:build_centos7
- laoshanxi/appmesh:build_centos8
- laoshanxi/appmesh:build_ubuntu18
- laoshanxi/appmesh:build_ubuntu20
- laoshanxi/appmesh:build_ubuntu18_arm64
