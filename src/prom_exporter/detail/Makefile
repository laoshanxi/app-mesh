include ../../../make.def
TARGET = libprom_detail.a
OEXT = o

INCLUDES = -I../

all : format $(TARGET) 

## source and object files 
SRCS = builder.cc ckms_quantiles.cc time_window_quantiles.cc utils.cc

OBJS = $(SRCS:.cc=.$(OEXT))

# =============
# File suffixes
# =============
.SUFFIXES: .cc .$(OEXT)

# ====================
#compile all cc files
# ====================
%.${OEXT}: %.cc
	${CXX} ${CXXFLAGS} ${INCLUDES} -DBUILD_TAG=${BUILD_TAG} -c $<;
	# cleanup.py ${CXX} ${CXXFLAGS} ${INCLUDES} -DBUILD_TAG=${BUILD_TAG} -c $<;

# Executable binary
$(TARGET): $(OBJS) 
	# ar cru $@ $(OBJS)

format:
	#dos2unix *.cc *.h

.PHONY: clean
clean:
	rm -f *.$(OEXT) $(TARGET) 
