include ../../make.def
TARGET = appc
OEXT = o

INCLUDES = -I/usr/local/include
DEP_LIBS = -L/usr/local/ace/lib/ -L/usr/local/lib64/boost -L/usr/local/lib64 -lpthread -lssl -lcrypto -lcpprest -lboost_system -lboost_program_options -lACE -Wl,-Bstatic -llog4cpp -Wl,-Bdynamic

all : $(TARGET) 

# ====================
# source and object files
# ====================
SRCS = main.cpp \
	ArgumentParser.cpp \
	../common/Utility.cpp

OBJS = $(SRCS:.cpp=.$(OEXT))

# ====================
# File suffixes
# ====================
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
