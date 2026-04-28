.DELETE_ON_ERROR:

.PHONY : all release debug shared static clean clean_all clean_objects clean_static clean_shared install install-strip install_shared install_static install_headers uninstall

RELEASE_CFLAGS = -O3 -flto
DEBUG_CFLAGS = -ggdb -Og
ALL_CFLAGS =

ifdef DEBUG
 ALL_CFLAGS += $(DEBUG_CFLAGS)
else ifdef RELEASE
 ALL_CFLAGS += $(RELEASE_CFLAGS)
endif
ALL_CFLAGS += $(CFLAGS)

STATIC =
SHARED = 1
ifdef STATIC
 TARGET += static
endif
ifdef SHARED
 TARGET += shared
endif

all : $(TARGET)

release : ALL_CFLAGS += $(RELEASE_CFLAGS)
release : all
debug : ALL_CFLAGS += $(DEBUG_CFLAGS)
debug : all

OBJECTS = _httplib_utils.o

SERVER = 1
CLIENT = 1
ifdef CLIENT
 OBJECTS += http_client.o
endif
ifdef SERVER
 OBJECTS += http_server.o
endif

BUILD_DIR = build
SOURCES := $(OBJECTS:.o=.c)
HEADERS := httplib.h $(OBJECTS:.o=.h)
OBJECTS := $(addprefix $(BUILD_DIR)/,$(OBJECTS))

VERSION_MAJOR := 2
VERSION_MINOR := 3
SONAME := libhttp.so.$(VERSION_MAJOR)
REALNAME := $(SONAME).$(VERSION_MINOR)
STATICNAME := libhttp-$(VERSION_MAJOR).$(VERSION_MINOR).a

MACROS = $(if $(PORT),-D'PORT=$(PORT)') $(if $(TIMEOUT),-D'TIMEOUT=$(TIMEOUT)') $(if $(TIMEOUT_USEC),-D'TIMEOUT_USEC=$(TIMEOUT_USEC)')

shared : $(BUILD_DIR)/$(REALNAME)
$(BUILD_DIR)/$(REALNAME) : $(HEADERS) $(SOURCES) | $(BUILD_DIR)
	$(CC) -shared -fPIC -Wl,-soname,$(SONAME) $(MACROS) $(CPPFLAGS) $(ALL_CFLAGS) $(LDFLAGS) $(SOURCES) -o $(BUILD_DIR)/$(REALNAME) $(LDLIBS)

AR = gcc-ar
ARFLAGS = rvcs
static : $(BUILD_DIR)/$(STATICNAME)
$(BUILD_DIR)/$(STATICNAME) : $(OBJECTS)
	$(AR) $(ARFLAGS) $(BUILD_DIR)/$(STATICNAME) $(OBJECTS)

$(OBJECTS) : httplib.h _httplib_utils.h | $(BUILD_DIR)
$(OBJECTS) : $(BUILD_DIR)/%.o : %.h
$(OBJECTS) : $(BUILD_DIR)/%.o : %.c
	$(CC) -c $(MACROS) $(CPPFLAGS) $(ALL_CFLAGS) $< -o $@
$(BUILD_DIR) :
	-mkdir $(BUILD_DIR)

clean : clean_all
clean_all:
	-rm -r $(BUILD_DIR)
clean_objects :
	-rm $(BUILD_DIR)/*.o
clean_static :
	-rm $(BUILD_DIR)/$(STATICNAME)
clean_shared :
	-rm $(BUILD_DIR)/$(REALNAME)

INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644
prefix = /usr/local
exec_prefix = $(prefix)
includedir = $(prefix)/include
libdir = $(exec_prefix)/lib

LDCONFIG = ldconfig
install : $(addprefix install_,$(TARGET)) install_headers
install-strip : STRIP = 1
install-strip : install
install_shared : shared | $(DESTDIR)$(libdir)/
	$(INSTALL_PROGRAM) $(if $(STRIP),-s) $(BUILD_DIR)/$(REALNAME) $(DESTDIR)$(libdir)/
	$(LDCONFIG) -r $(DESTDIR) -n $(libdir)/
	ln -s $(SONAME) $(DESTDIR)$(libdir)/libhttp.so
install_static : static | $(DESTDIR)$(libdir)/
	$(INSTALL_DATA) $(if $(STRIP),-s) $(BUILD_DIR)/$(STATICNAME) $(DESTDIR)$(libdir)/
$(DESTDIR)$(libdir)/ :
	$(INSTALL) -d $(DESTDIR)$(libdir)/
install_headers : | $(DESTDIR)$(includedir)/http_lib/
	$(INSTALL_DATA) $(filter-out _httplib_utils.h,$(HEADERS)) $(DESTDIR)$(includedir)/http_lib/
$(DESTDIR)$(includedir)/http_lib/ :
	$(INSTALL) -d $(DESTDIR)$(includedir)/http_lib/
uninstall :
	-rm $(DESTDIR)$(libdir)/$(REALNAME)
	-rm $(DESTDIR)$(libdir)/$(SONAME)
	-rm $(DESTDIR)$(libdir)/libhttp.so
	-rm $(DESTDIR)$(libdir)/$(STATICNAME)
	-rm -r $(DESTDIR)$(includedir)/http_lib
