# Compiler options
#----------------------------------------------------------
CC= gcc -std=gnu99

INCLUDES= $(HOME)/include

# the -Wno-deprecated-declarations is for OpenSSL
#CFLAGS = -Wall -Werror -DRHO_TRACE -DRHO_DEBUG -I $(INCLUDES)
CFLAGS = -Wall -Werror -I $(INCLUDES)

# Utilities
#----------------------------------------------------------
AR= ar rcu
RANLIB= ranlib
RM= rm -f
MKDIR= mkdir -p
INSTALL= install -p
INSTALL_DATA= $(INSTALL) -m 0644

# If you don't have install, you can use "cp" instead.
# 
# INSTALL= cp -p
# INSTAL_DATA= $(INSTALL)


# Install Location
# See, also, the local target
#----------------------------------------------------------
INSTALL_TOP= /usr/local
INSTALL_INC= $(INSTALL_TOP)/include
INSTALL_LIB= $(INSTALL_TOP)/lib


# == END OF USER SETTINGS -- NO NEED TO CHANGE ANYTHING BELOW THIS LINE =======

# Headers to intsall
#----------------------------------------------------------
TO_INC= bd.h

# Library to install
#----------------------------------------------------------
TO_LIB= libbd.a

BD_A= libbd.a

OBJS = \
	   bd_util.o \
	   mt.o \
	   bdstd.o \
	   bdcrypt.o \
	   bdverity.o \
	   bdvericrypt.o

# Targets start here
#----------------------------------------------------------
all: $(BD_A)

$(BD_A): $(OBJS)
	$(AR) $@ $(OBJS)
	$(RANLIB) $@

install:
	$(MKDIR) $(INSTALL_INC) $(INSTALL_LIB)
	$(INSTALL_DATA) $(TO_INC) $(INSTALL_INC)
	$(INSTALL_DATA) $(TO_LIB) $(INSTALL_LIB)

uninstall:
	cd $(INSTALL_INC) && $(RM) $(TO_INC)
	cd $(INSTALL_LIB) && $(RM) $(TO_LIB)

local:
	$(MAKE) install INSTALL_TOP=../install

clean:
	$(RM) $(OBJS) $(BD_A)

echo:
	@echo "CC= $(CC)"
	@echo "CFLAGS= $(CFLAGS)"
	@echo "AR= $(AR)"
	@echo "RANLIB= $(RANLIB)"
	@echo "RM= $(RM)"
	@echo "MKDIR= $(MKDIR)"
	@echo "INSTALL= $(INSTALL)"
	@echo "INSTALL_DATA= $(INSTALL_DATA)"
	@echo "TO_INC= $(TO_INC)"
	@echo "TO_LIB= $(TO_LIB)"
	@echo "INSTALL_TOP= $(INSTALL_TOP)"
	@echo "INSTALL_INC= $(INSTALL_INC)"
	@echo "INSTALL_LIB= $(INSTALL_LIB)"

# DO NOT DELETE

bd_util.o: bd_util.c bd_util.h
mt.o: mt.c mt.h
bdstd.o: bdstd.c bd.h
bdcrypt.o: bdcrypt.c bd.h
bdverity.o: bdverity.c bd.h
bdvericrypt.o: bdvericrypt.c bd.h

.PHONY: clean echo local install uninstall

