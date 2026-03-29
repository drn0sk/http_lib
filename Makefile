.DELETE_ON_ERROR:

.PHONY : all release debug shared static clean clean_all clean_objects clean_libhttp.a clean_libhttp.so install install-strip install_shared install_static install_headers uninstall

CFLAGS = -g -O # defaults if CFLAGS is not explicitly set
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

SERVER = true
CLIENT = true
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

shared : $(BUILD_DIR)/libhttp.so
$(BUILD_DIR)/libhttp.so : $(HEADERS) $(SOURCES) | $(BUILD_DIR)
	$(CC) -shared -fPIC $(if $(PORT),-D'PORT=$(PORT)') $(CPPFLAGS) $(ALL_CFLAGS) $(LDFLAGS) $(SOURCES) -o $(BUILD_DIR)/libhttp.so $(LDLIBS)

AR = gcc-ar
ARFLAGS = rvcs
static : $(BUILD_DIR)/libhttp.a
$(BUILD_DIR)/libhttp.a : $(OBJECTS)
	$(AR) $(ARFLAGS) $(BUILD_DIR)/libhttp.a $(OBJECTS)

$(OBJECTS) : httplib.h _httplib_utils.h | $(BUILD_DIR)
$(OBJECTS) : $(BUILD_DIR)/%.o : %.h
$(OBJECTS) : $(BUILD_DIR)/%.o : %.c
	$(CC) -c $(if $(PORT),-D'PORT=$(PORT)') $(CPPFLAGS) $(ALL_CFLAGS) $< -o $@
$(BUILD_DIR) :
	-mkdir $(BUILD_DIR)

clean : clean_all
clean_all:
	-rm -r $(BUILD_DIR)
clean_objects :
	-rm $(BUILD_DIR)/*.o
clean_libhttp.a :
	-rm $(BUILD_DIR)/libhttp.a
clean_libhttp.so :
	-rm $(BUILD_DIR)/libhttp.so

INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644
prefix = /usr/local
exec_prefix = $(prefix)
includedir = $(prefix)/include
libdir = $(exec_prefix)/lib

install : $(addprefix install_,$(TARGET)) install_headers
install-strip : STRIP = 1
install-strip : install
install_shared : shared
	$(INSTALL_PROGRAM) $(if $(STRIP),-s) $(BUILD_DIR)/libhttp.so $(DESTDIR)$(libdir)/
install_static : static
	$(INSTALL_DATA) $(if $(STRIP),-s) $(BUILD_DIR)/libhttp.a $(DESTDIR)$(libdir)/
install_headers : | $(DESTDIR)$(includedir)/libhttp/
	$(INSTALL_DATA) $(filter-out _httplib_utils.h,$(HEADERS)) $(DESTDIR)$(includedir)/libhttp/
$(DESTDIR)$(includedir)/libhttp/ :
	mkdir $(DESTDIR)$(includedir)/libhttp/
uninstall :
	-rm $(DESTDIR)$(libdir)/libhttp.so
	-rm $(DESTDIR)$(libdir)/libhttp.a
	-rm -r $(DESTDIR)$(includedir)/libhttp
