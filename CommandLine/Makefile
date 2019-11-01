include ../make.def
TARGET = appc
CXX = g++
CXXFLAGS = -std=c++11 -ggdb3 -Wall -O2
OEXT = o

INCLUDES = -I/usr/local/include -I/usr/local/ace/include/
DEP_LIBS = -L/usr/local/ace/lib/ -L/usr/local/lib -L/usr/local/lib64 -lpthread -lssl -lcrypto -lcpprest -lboost_system -lboost_program_options -lACE -Wl,-Bstatic -llog4cpp -ljsoncpp -Wl,-Bdynamic \
           -L../common -lcommon

all : format $(TARGET) 

## source and object files 
SRCS = main.cpp \
	ArgumentParser.cpp

OBJS = $(SRCS:.cpp=.$(OEXT))

# =============
# File suffixes
# =============
.SUFFIXES: .cpp .$(OEXT)

# ====================
#compile all cpp files
# ===================
%.${OEXT}: %.cpp
	${CXX} ${CXXFLAGS} ${INCLUDES} -DBUILD_TAG=${BUILD_TAG} -c $<;
	# cleanup.py ${CXX} ${CXXFLAGS} ${INCLUDES} -DBUILD_TAG=${BUILD_TAG} -c $<;

# Executable binary
$(TARGET): $(OBJS) 
	$(CXX) ${CXXFLAGS} -o $@ $^ $(DEP_LIBS)

format:
	#dos2unix *.cpp

.PHONY: clean
clean:
	rm -f *.$(OEXT) $(TARGET) 
