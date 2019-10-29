include ../make.def
TARGET = common.a
CXX = g++
CXXFLAGS = -std=c++11 -ggdb3 -Wall -O2
OEXT = o

INCLUDES = -I/usr/local/ace/include/

all : format $(TARGET) 

## source and object files 
SRCS = TimeZoneHelper.cpp Utility.cpp HttpRequest.cpp

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
	ar cru $@ $(OBJS)

format:
	#dos2unix *.cpp *.h

.PHONY: clean
clean:
	rm -f *.$(OEXT) $(TARGET) 
