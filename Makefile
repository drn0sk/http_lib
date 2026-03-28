.DELETE_ON_ERROR:

.PHONY : default release debug clean clean_all clean_libhttp.o clean_libhttp.a clean_libhttp.so

RELEASE_CFLAGS = -O3 -flto
DEBUG_CFLAGS = -ggdb -Og
CFLAGS = $(EXTRA_CFLAGS)

_null  :=
_space := $(_null) #
_comma := ,

LDFLAGS := $(if $(LDFLAGS),-Wl,$(subst $(_space),$(_comma),$(strip $(LDFLAGS))))

ifdef DEBUG
 CFLAGS += $(DEBUG_CFLAGS)
else ifdef RELEASE
 CFLAGS += $(RELEASE_CFLAGS)
endif

BUILD_DIR = build

ifndef STATIC
 # shared library built if STATIC is not set
 TARGET = $(BUILD_DIR)/libhttp.so
 CFLAGS += -fPIC
else 
 TARGET = $(BUILD_DIR)/libhttp.a
endif

default : $(TARGET)

release : CFLAGS += $(RELEASE_CFLAGS)
release : default

debug : CFLAGS += $(DEBUG_CFLAGS)
debug : default

HEADERS = httplib.h _httplib_utils.h
OBJECTS = _httplib_utils.o
#SOURCES = _httplib_utils.c

SERVER = true
CLIENT = true

ifdef CLIENT
 #HEADERS += http_client.h
 OBJECTS += http_client.o
 #SOURCES += http_client.c
endif
ifdef SERVER
 #HEADERS += http_server.h
 OBJECTS += http_server.o
 #SOURCES += http_server.c
endif

OBJECTS := $(addprefix $(BUILD_DIR)/,$(OBJECTS))

$(BUILD_DIR)/libhttp.so : $(OBJECTS)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/libhttp.so $(OBJECTS)

AR = gcc-ar

$(BUILD_DIR)/libhttp.a : $(OBJECTS)
	$(AR) -rcs $(BUILD_DIR)/libhttp.a $(OBJECTS)

$(OBJECTS) : $(HEADERS) | $(BUILD_DIR)
$(OBJECTS) : $(BUILD_DIR)/%.o : %.h
$(OBJECTS) : $(BUILD_DIR)/%.o : %.c
	$(CC)	-c $(CFLAGS) \
		$(if $(PORT),-D'PORT=$(PORT)') \
		-o $@ $<
$(BUILD_DIR) :
	mkdir -p $(BUILD_DIR)

clean : clean_all
clean_all:
	-rm -r $(BUILD_DIR)
clean_libhttp.o :
	-rm $(BUILD_DIR)/libhttp.o
clean_libhttp.a :
	-rm $(BUILD_DIR)/libhttp.a
clean_libhttp.so :
	-rm $(BUILD_DIR)/libhttp.so
