# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT := ec_conv_nif

ifeq ($(origin ERTS_INCLUDE_DIR), undefined)
ERTS_INCLUDE_DIR ::= $(shell erl -noshell -eval "io:format(\"~ts/erts-~ts/include/\", [code:root_dir(), erlang:system_info(version)]), halt().")
endif
ifeq ($(origin ERL_INTERFACE_INCLUDE_DIR), undefined)
ERL_INTERFACE_INCLUDE_DIR ::= $(shell erl -noshell -eval "io:format(\"~ts\", [code:lib_dir(erl_interface, include)]), halt().")
endif
ifeq ($(origin ERL_INTERFACE_LIB_DIR), undefined)
ERL_INTERFACE_LIB_DIR ::= $(shell erl -noshell -eval "io:format(\"~ts\", [code:lib_dir(erl_interface, lib)]), halt().")
endif

C_SRC_DIR = $(CURDIR)
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT).so

# System type and C compiler/flags.

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Darwin)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
	LDFLAGS ?= -flat_namespace -undefined suppress
else ifeq ($(UNAME_SYS), FreeBSD)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
else ifeq ($(UNAME_SYS), OpenBSD)
	CC ?= cc
	CFLAGS ?= -O2 -std=gnu99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O2 -finline-functions -Wall
	OSSL_CFLAGS :=
	OSSL_LIBS := -lcrypto
else ifeq ($(UNAME_SYS), Linux)
	CC ?= gcc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
	OSSL_CFLAGS := $(shell pkg-config --cflags openssl)
	OSSL_LIBS := $(shell pkg-config --libs-only-L openssl) -lcrypto
else ifeq ($(UNAME_SYS), SunOS)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
	OSSL_CFLAGS := $(shell pkg-config --cflags openssl)
	OSSL_LIBS := $(shell pkg-config --libs-only-L openssl) -lcrypto
endif

CFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR) -I $(ERL_INTERFACE_INCLUDE_DIR)
CXXFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR) -I $(ERL_INTERFACE_INCLUDE_DIR)

LDLIBS += -L $(ERL_INTERFACE_LIB_DIR) -lei
LDFLAGS += -shared

CFLAGS += -fno-omit-frame-pointer -O2 -fno-inline-functions

CFLAGS += $(OSSL_CFLAGS)
LDLIBS += $(OSSL_LIBS)

V ?= 0

# Verbosity.

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(?F);
cpp_verbose = $(cpp_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.c" -o -name "*.C" -o -name "*.cc" -o -name "*.cpp" \))
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

$(C_SRC_OUTPUT): $(OBJECTS)
	@mkdir -p $(BASEDIR)/priv/
	$(link_verbose) $(CC) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $(C_SRC_OUTPUT)

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.C
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

clean:
	@rm -f $(C_SRC_OUTPUT) $(OBJECTS)
