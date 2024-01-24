#!/bin/sh
################################################################################
## This Script file is used to build rpm/deb package and launched by cmake cmd
################################################################################

set -x
rm -rf *.rpm
rm -rf *.deb
export PACKAGE_HOME=${CMAKE_BINARY_DIR}/home
export INSTALL_LOCATION=/opt/appmesh
export GOARCH=$(go env GOARCH)

rm -rf ${PACKAGE_HOME}
mkdir -p ${PACKAGE_HOME}/ssl
mkdir -p ${PACKAGE_HOME}/script
mkdir -p ${PACKAGE_HOME}/lib64
mkdir -p ${PACKAGE_HOME}/bin
cp ${CMAKE_BINARY_DIR}/gen/appc ${PACKAGE_HOME}/bin/
cp ${CMAKE_BINARY_DIR}/gen/appsvc ${PACKAGE_HOME}/bin/
cp ${CMAKE_BINARY_DIR}/gen/agent ${PACKAGE_HOME}/bin/

cp ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/config.json ${PACKAGE_HOME}/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/security/security.json ${PACKAGE_HOME}/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/security/ldapplugin/ldap.json ${PACKAGE_HOME}/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/app*.sh ${PACKAGE_HOME}/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/*.service ${PACKAGE_HOME}/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/ssl_cert_generate.sh ${PACKAGE_HOME}/ssl/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/cli/bash_completion.sh ${PACKAGE_HOME}/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/prom*.yml ${PACKAGE_HOME}/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/docker*.yaml ${PACKAGE_HOME}/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/*.html ${PACKAGE_HOME}/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/python/py_exec.py ${PACKAGE_HOME}/bin/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/cli/container_monitor.py ${PACKAGE_HOME}/bin/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/cli/appmesh_arm.py ${PACKAGE_HOME}/bin/
cp /usr/local/bin/cfssl ${PACKAGE_HOME}/ssl/
cp /usr/local/bin/cfssljson ${PACKAGE_HOME}/ssl/
cp /usr/local/bin/qrc ${PACKAGE_HOME}/bin/
cp -r ${CMAKE_CURRENT_SOURCE_DIR}/script/apps ${PACKAGE_HOME}

chmod +x ${PACKAGE_HOME}/script/*.sh

export LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib:${LD_LIBRARY_PATH}
ldd ${CMAKE_BINARY_DIR}/gen/appc | grep boost | awk '{cmd="cp "$3" ${PACKAGE_HOME}/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_BINARY_DIR}/gen/appc | grep libcurlpp | awk '{cmd="cp "$3" ${PACKAGE_HOME}/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_BINARY_DIR}/gen/appsvc | grep boost | awk '{cmd="cp "$3" ${PACKAGE_HOME}/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_BINARY_DIR}/gen/appsvc | grep ACE | awk '{cmd="cp "$3" ${PACKAGE_HOME}/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_BINARY_DIR}/gen/appsvc | grep libssl | awk '{cmd="cp "$3" ${PACKAGE_HOME}/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_BINARY_DIR}/gen/appsvc | grep libcrypto | awk '{cmd="cp "$3" ${PACKAGE_HOME}/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_BINARY_DIR}/gen/appsvc | grep log4cpp | awk '{cmd="cp "$3" ${PACKAGE_HOME}/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_BINARY_DIR}/gen/appsvc | grep oath | awk '{cmd="cp "$3" ${PACKAGE_HOME}/lib64";print(cmd);system(cmd)}'

GLIBC_VERION=$(ldd --version | head -n 1 | tr ' ' '\n' | tail -n 1)
GCC_VERION=$(gcc -dumpversion)

# Read the nfpm config template from file
template=$(cat "${CMAKE_CURRENT_SOURCE_DIR}/script/nfpm.yaml")
# Substitute environment variables
config=$(echo "$template" | envsubst)
# Save the substituted config to a temporary file
echo "$config" > ${CMAKE_BINARY_DIR}/nfpm_config.yaml
nfpm pkg --config ${CMAKE_BINARY_DIR}/nfpm_config.yaml --packager deb
nfpm pkg --config ${CMAKE_BINARY_DIR}/nfpm_config.yaml --packager rpm

mv appmesh*.rpm ${PROJECT_NAME}_${PROJECT_VERSION}_gcc_${GCC_VERION}_glibc_${GLIBC_VERION}_$(arch).rpm
mv appmesh*.deb ${PROJECT_NAME}_${PROJECT_VERSION}_gcc_${GCC_VERION}_glibc_${GLIBC_VERION}_$(arch).deb
