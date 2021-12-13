#!/bin/sh
################################################################################
## This Script file is used to build rpm/deb package and launched by cmake cmd
################################################################################

set -x
rm -rf *.rpm
rm -rf *.deb
mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/
mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/ssl
mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script
mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/lib64
mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/sdk
mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/bin
cp ${CMAKE_CURRENT_BINARY_DIR}/bin/appc ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/bin/
cp ${CMAKE_CURRENT_BINARY_DIR}/bin/appsvc ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/bin/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/config.json ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/security/security.json ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/security/ldapplugin/ldap.json ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/app*.sh ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/rpm*.sh ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/*.service ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/ssl_cert_generate.sh ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/ssl/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/cli/bash_completion.sh ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/*.yml ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/script/*.yaml ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/python/appmesh_client.py ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/sdk/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/cli/container_monitor.py ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/bin/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/cli/appmesh_arm.py ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/bin/
cp ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk/python/py_exec.py ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/bin/
cp /usr/bin/cfssl ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/ssl/
cp /usr/bin/cfssljson ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/ssl/
cp ${CMAKE_CURRENT_BINARY_DIR}/dockeragent ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/bin/
# upx ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/bin/dockeragent
chmod +x ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/*.sh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib64:/usr/local/lib/:/usr/local/ace/lib/
ldd ${CMAKE_CURRENT_BINARY_DIR}/bin/appc | grep boost | awk '{cmd="cp "$3" ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_CURRENT_BINARY_DIR}/bin/appsvc | grep boost | awk '{cmd="cp "$3" ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_CURRENT_BINARY_DIR}/bin/appsvc | grep ACE | awk '{cmd="cp "$3" ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_CURRENT_BINARY_DIR}/bin/appsvc | grep cpprest | awk '{cmd="cp "$3" ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_CURRENT_BINARY_DIR}/bin/appsvc | grep libssl | awk '{cmd="cp "$3" ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_CURRENT_BINARY_DIR}/bin/appsvc | grep libcrypto | awk '{cmd="cp "$3" ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/lib64";print(cmd);system(cmd)}'
ldd ${CMAKE_CURRENT_BINARY_DIR}/bin/appsvc | grep log4cpp | awk '{cmd="cp "$3" ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/lib64";print(cmd);system(cmd)}'

rm ${CMAKE_CURRENT_BINARY_DIR}/bin/appc
rm ${CMAKE_CURRENT_BINARY_DIR}/bin/appsvc

GLIBC_VERION=$(ldd --version | head -n 1 | tr ' ' '\n' | tail -n 1)
GCC_VERION=$(gcc -dumpversion)

fpm -s dir -t rpm -v ${PROJECT_VERSION} -n ${PROJECT_NAME} -d 'psmisc,net-tools,curl,openldap-devel' --vendor laoshanxi --description ${PROJECT_NAME} --post-install ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/rpm_post_install.sh \
  --before-remove ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/rpm_pre_uninstall.sh --after-remove ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/rpm_post_uninstall.sh -C ${CMAKE_CURRENT_BINARY_DIR}/bin
fpm -s dir -t deb -v ${PROJECT_VERSION} -n ${PROJECT_NAME} -d 'psmisc,net-tools,curl,libldap2-dev' --vendor laoshanxi --description ${PROJECT_NAME} --post-install ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/rpm_post_install.sh \
  --before-remove ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/rpm_pre_uninstall.sh --after-remove ${CMAKE_CURRENT_BINARY_DIR}/bin/opt/appmesh/script/rpm_post_uninstall.sh -C ${CMAKE_CURRENT_BINARY_DIR}/bin

mv appmesh*.rpm ${PROJECT_NAME}_${PROJECT_VERSION}_gcc_${GCC_VERION}_glibc_${GLIBC_VERION}_$(arch).rpm
mv appmesh*.deb ${PROJECT_NAME}_${PROJECT_VERSION}_gcc_${GCC_VERION}_glibc_${GLIBC_VERION}_$(arch).deb