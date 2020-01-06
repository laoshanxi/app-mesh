include ../../make.def
TARGET = appsvc
OEXT = o

# https://blog.csdn.net/humadivinity/article/details/78890754
# boost_thread is not needed, linked here is used to packed for cpprest 
INCLUDES = -I/usr/local/ace/include/ -I/usr/local/include -I../prom_exporter
DEP_LIBS = -L../common -lcommon -L../prom_exporter -lprom_exporter -L/usr/local/ace/lib/ -L/usr/local/lib64/boost -L/usr/local/lib64 -lpthread -lcrypto -lssl -lACE -lcpprest -lboost_thread -lboost_system -lboost_regex -Wl,-Bstatic -llog4cpp -Wl,-Bdynamic

all : $(TARGET) 

## source and object files
SRCS = \
	main.cpp \
	Application.cpp \
	ApplicationShortRun.cpp \
	ApplicationPeriodRun.cpp \
	Configuration.cpp \
	RestHandler.cpp \
	PrometheusRest.cpp \
	AppProcess.cpp \
	DockerProcess.cpp \
	MonitoredProcess.cpp \
	DailyLimitation.cpp \
	ResourceLimitation.cpp \
	ResourceCollection.cpp \
	LinuxCgroup.cpp \
	User.cpp \
	Role.cpp \
	Label.cpp \
	HealthCheckTask.cpp \
	PersistManager.cpp \
	TimerHandler.cpp
		

OBJS = $(SRCS:.cpp=.$(OEXT))

# =============
# File suffixes
# =============
.SUFFIXES: .cpp .$(OEXT)

# ====================
#compile all cpp files
# ====================
%.${OEXT}: %.cpp
	${CXX} ${CXXFLAGS} ${INCLUDES} -DBUILD_TAG=${BUILD_TAG} -c $<;
	# cleanup.py ${CXX} ${CXXFLAGS} ${INCLUDES} -DBUILD_TAG=${BUILD_TAG} -c $<;

# Executable binary
$(TARGET): $(OBJS) 
	$(CXX) ${CXXFLAGS} -o $@ $^ $(DEP_LIBS)

.PHONY: clean
clean:
	rm -f *.$(OEXT) $(TARGET) 
