VERSION=1.0
PACKAGE_NAME=appmanager
BUILD_DATE=$(shell date "+%Y%m%d%H%M")
BUILD_TAG=${PACKAGE_NAME}-${VERSION}-${BUILD_DATE}
VENDER=github

RELEASE_DIR=./release
INSTALL_DIR=/opt/${PACKAGE_NAME}
TMP_DIR=${RELEASE_DIR}${INSTALL_DIR}
TMP_LIB_DIR=${TMP_DIR}/lib64
LDPATH=$(LD_LIBRARY_PATH):/usr/local/lib64:/usr/local/lib/:/usr/local/ace/lib/

all:
	echo ${BUILD_TAG}
	cd common; make
	cd ApplicationManager; make
	cd CommandLine; make
	make build_dir
	make deb
	make rpm

build_dir:
	rm -rf ${RELEASE_DIR}
	mkdir -p ${TMP_DIR}/script
	mkdir -p ${TMP_LIB_DIR}
	cp ./CommandLine/appc ${TMP_DIR}/
	cp ./ApplicationManager/appsvc ${TMP_DIR}/
	cp ./ApplicationManager/appsvc.json ${TMP_DIR}/
	cp ./script/*.sh ${TMP_DIR}/script
	cp ./script/app.bashrc ${TMP_DIR}/script
	cp ./script/server.crt ${TMP_DIR}/
	cp ./script/server.key ${TMP_DIR}/
	chmod +x ${TMP_DIR}/script/*.sh
	dos2unix ${TMP_DIR}/script/*.sh
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./ApplicationManager/appsvc | grep boost | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./CommandLine/appc | grep boost | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./ApplicationManager/appsvc | grep jsoncpp | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./ApplicationManager/appsvc | grep ACE | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./ApplicationManager/appsvc | grep cpprest | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./ApplicationManager/appsvc | grep ssl | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./ApplicationManager/appsvc | grep crypto | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./ApplicationManager/appsvc | grep log4cpp | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	
deb:
	rm -f *.deb
	fpm -s dir -t deb -v ${VERSION} -n ${PACKAGE_NAME} --vendor ${VENDER} --description ${VENDER} --post-install ${TMP_DIR}/script/install.sh --before-remove ${TMP_DIR}/script/pre_uninstall.sh --after-remove ${TMP_DIR}/script/uninstall.sh -C ${RELEASE_DIR}
rpm:
	rm -f *.rpm
	fpm -s dir -t rpm -v ${VERSION} -n ${PACKAGE_NAME} --vendor ${VENDER} --description ${VENDER} --post-install ${TMP_DIR}/script/install.sh --before-remove ${TMP_DIR}/script/pre_uninstall.sh --after-remove ${TMP_DIR}/script/uninstall.sh -C ${RELEASE_DIR}
cppcheck:
	cppcheck --enable=all --quiet --std=c++11 --platform=native .
install:
	dpkg -i ./${PACKAGE_NAME}_${VERSION}_amd64.deb
	
uninstall:
	dpkg -P ${PACKAGE_NAME}

clean:
	cd CommandLine; make clean
	cd common; make clean
	cd ApplicationManager; make clean
	rm -rf release
	rm -f *.deb
	rm -f *.rpm
