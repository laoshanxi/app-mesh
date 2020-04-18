include make.def
RELEASE_DIR=./release
INSTALL_DIR=/opt/${PACKAGE_NAME}
TMP_DIR=${RELEASE_DIR}${INSTALL_DIR}
TMP_LIB_DIR=${TMP_DIR}/lib64
LDPATH=$(LD_LIBRARY_PATH):/usr/local/lib64:/usr/local/lib/:/usr/local/ace/lib/

all:
	echo ${BUILD_TAG}
	make code
	make deb
	make rpm

code:
	cd src; make
	make build_dir

build_dir:
	rm -rf ${RELEASE_DIR}
	mkdir -p ${TMP_DIR}/script
	mkdir -p ${TMP_DIR}/ssl
	mkdir -p ${TMP_LIB_DIR}
	cp ./src/cli/appc ${TMP_DIR}/
	cp ./src/daemon/appsvc ${TMP_DIR}/
	cp ./src/daemon/appsvc.json ${TMP_DIR}/
	cp ./script/app*.sh ${TMP_DIR}/script
	cp ./script/rpm*.sh ${TMP_DIR}/script
	cp ./script/*.service ${TMP_DIR}/script
	cp ./ssl/*.sh ${TMP_DIR}/ssl
	cp ./src/cli/bash_completion.sh ${TMP_DIR}/script
	cp /usr/local/bin/cfssl ${TMP_DIR}/ssl
	cp /usr/local/bin/cfssljson ${TMP_DIR}/ssl
	chmod +x ${TMP_DIR}/script/*.sh
	-dos2unix ${TMP_DIR}/script/*.sh
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./src/daemon/appsvc | grep boost | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./src/cli/appc | grep boost | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./src/daemon/appsvc | grep ACE | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./src/daemon/appsvc | grep cpprest | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./src/daemon/appsvc | grep ssl | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./src/daemon/appsvc | grep crypto | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	env LD_LIBRARY_PATH=${LDPATH} \
	ldd ./src/daemon/appsvc | grep log4cpp | awk '{cmd="cp "$$3" ${TMP_LIB_DIR}";print(cmd);system(cmd)}'
	
deb:
	rm -f *.deb
	fpm -s dir -t deb -v ${VERSION} -n ${PACKAGE_NAME} -d 'psmisc' --vendor ${VENDER} --description ${VENDER} --post-install ${TMP_DIR}/script/rpm_post_install.sh --before-remove ${TMP_DIR}/script/rpm_pre_uninstall.sh --after-remove ${TMP_DIR}/script/rpm_post_uninstall.sh -C ${RELEASE_DIR}
rpm:
	rm -f *.rpm
	/usr/local/bin/fpm -s dir -t rpm -v ${VERSION} -n ${PACKAGE_NAME} -d 'psmisc,libicu' --vendor ${VENDER} --description ${VENDER} --post-install ${TMP_DIR}/script/rpm_post_install.sh --before-remove ${TMP_DIR}/script/rpm_pre_uninstall.sh --after-remove ${TMP_DIR}/script/rpm_post_uninstall.sh -C ${RELEASE_DIR}
cppcheck:
	cppcheck --enable=all --quiet --std=c++11 --platform=native .
install:
	-dpkg -i ./${PACKAGE_NAME}_${VERSION}_amd64.deb
	-yum install -y ./${PACKAGE_NAME}*.rpm
	
uninstall:
	-dpkg -P ${PACKAGE_NAME}
	-yum remove -y ${PACKAGE_NAME}

dev:
	-git pull
	make clean
	make
	-make uninstall
	make install

lines:
	find . -name "*.cpp" -or -name "*.h" -or -name "*.hpp" -or -name "*.c"  -or -name "*.sh" -or -name "Makefile" -or -name "Dockerfile" |xargs grep -v "^$$"|wc -l

clean:
	cd src; make clean
	rm -rf release
	rm -f *.deb
	rm -f *.rpm
