CXX      ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
INCLUDES  = -Isrc -isystem third_party
LDFLAGS  += -pthread

# --- Optional HTTPS support (needed to call the Claude API) ---------------------
# macOS: brew install openssl   Linux: apt install libssl-dev
# If OpenSSL is not found the server still builds and uses built-in explanations.
ifeq ($(shell uname),Darwin)
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
endif
ifneq ($(OPENSSL_PREFIX),)
  SSL_INC = -I$(OPENSSL_PREFIX)/include
  SSL_LIB = -L$(OPENSSL_PREFIX)/lib
endif
HASH := \#
HAVE_SSL := $(shell printf '%s\n' '$(HASH)include <openssl/ssl.h>' | $(CXX) $(SSL_INC) -E -x c++ - >/dev/null 2>&1 && echo 1)
ifeq ($(HAVE_SSL),1)
  SSL_FLAGS = -DCPPHTTPLIB_OPENSSL_SUPPORT $(SSL_INC)
  SSL_LDFLAGS = $(SSL_LIB) -lssl -lcrypto
  ifeq ($(shell uname),Darwin)
    SSL_FLAGS += -DCPPHTTPLIB_USE_CERTS_FROM_MACOS_KEYCHAIN
    SSL_LDFLAGS += -framework CoreFoundation -framework Security
  endif
endif

BUILD = build
SRC   = src/analyzer.cpp src/redact.cpp src/explainer.cpp

.PHONY: all server test run clean

all: server

$(BUILD):
	mkdir -p $(BUILD)

server: $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SSL_FLAGS) src/main.cpp $(SRC) -o $(BUILD)/scamshield-server $(LDFLAGS) $(SSL_LDFLAGS)
	@if [ "$(HAVE_SSL)" = "1" ]; then echo "Built with HTTPS support (Claude API enabled)."; \
	else echo "Built WITHOUT HTTPS support: install OpenSSL to enable Claude. Built-in explanations only."; fi

test: $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SSL_FLAGS) tests/test_analyzer.cpp src/analyzer.cpp -o $(BUILD)/test-analyzer
	./$(BUILD)/test-analyzer
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SSL_FLAGS) tests/test_ai.cpp $(SRC) -o $(BUILD)/test-ai $(LDFLAGS) $(SSL_LDFLAGS)
	./$(BUILD)/test-ai

run: server
	./$(BUILD)/scamshield-server

clean:
	rm -rf $(BUILD)
