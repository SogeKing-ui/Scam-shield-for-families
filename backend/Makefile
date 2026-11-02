CXX      ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
INCLUDES  = -Isrc -isystem third_party
LDFLAGS  += -pthread

# --- OpenSSL (needed for HTTPS to the Claude API, password hashing, and encryption) --------------
# macOS: brew install openssl@3        Linux: apt install libssl-dev
ifeq ($(shell uname),Darwin)
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
endif
ifneq ($(OPENSSL_PREFIX),)
  SSL_INC = -I$(OPENSSL_PREFIX)/include
  SSL_LIB = -L$(OPENSSL_PREFIX)/lib
endif
HASH := \#
HAVE_SSL := $(shell printf '%s\n' '$(HASH)include <openssl/ssl.h>' | $(CXX) $(SSL_INC) -E -x c++ - >/dev/null 2>&1 && echo 1)
SSL_FLAGS = -DCPPHTTPLIB_OPENSSL_SUPPORT $(SSL_INC)
SSL_LDFLAGS = $(SSL_LIB) -lssl -lcrypto -lsqlite3
ifeq ($(shell uname),Darwin)
  SSL_FLAGS += -DCPPHTTPLIB_USE_CERTS_FROM_MACOS_KEYCHAIN
  SSL_LDFLAGS += -framework CoreFoundation -framework Security
endif

BUILD = build
CORE  = src/analyzer.cpp src/redact.cpp src/explainer.cpp src/crypto.cpp
ACCT  = src/db.cpp src/store.cpp src/accounts.cpp src/mailer.cpp

.PHONY: all server test api-test run scorer clean check-ssl

all: server

$(BUILD):
	mkdir -p $(BUILD)

check-ssl:
	@if [ "$(HAVE_SSL)" != "1" ]; then \
	  echo "OpenSSL was not found. On a Mac run: brew install openssl@3   (then: make clean && make run)"; exit 1; fi

server: $(BUILD) check-ssl
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SSL_FLAGS) src/main.cpp $(CORE) $(ACCT) -o $(BUILD)/scamshield-server $(LDFLAGS) $(SSL_LDFLAGS)

test: $(BUILD) check-ssl
	$(CXX) $(CXXFLAGS) $(INCLUDES) tests/test_analyzer.cpp src/analyzer.cpp -o $(BUILD)/test-analyzer
	./$(BUILD)/test-analyzer
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SSL_FLAGS) tests/test_ai.cpp $(CORE) -o $(BUILD)/test-ai $(LDFLAGS) $(SSL_LDFLAGS)
	./$(BUILD)/test-ai
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SSL_FLAGS) tests/test_accounts.cpp src/analyzer.cpp src/crypto.cpp src/db.cpp src/store.cpp -o $(BUILD)/test-accounts $(LDFLAGS) $(SSL_LDFLAGS)
	./$(BUILD)/test-accounts

# Starts the server on a spare port with a throwaway database and exercises the whole account flow.
api-test: server
	python3 tests/api_test.py

scorer: $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) ../tools/scorer.cpp src/analyzer.cpp -o $(BUILD)/scorer

run: server
	./$(BUILD)/scamshield-server

clean:
	rm -rf $(BUILD)
