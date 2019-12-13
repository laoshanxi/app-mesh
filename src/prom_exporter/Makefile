include ../../make.def
TARGET = libprom_exporter.a
OEXT = o

INCLUDES = -I.

all : format $(TARGET) 

## source and object files 
SRCS = check_names.cc counter.cc family.cc gauge.cc histogram.cc registry.cc serializer.cc summary.cc text_serializer.cc \
       detail/builder.cc detail/ckms_quantiles.cc detail/time_window_quantiles.cc detail/utils.cc

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
	ar cru $@ $(OBJS)

format:
	cd detail; make
	#dos2unix *.cc *.h

.PHONY: clean
clean:
	rm -f *.$(OEXT) $(TARGET) 
