CXX      ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
INCLUDES  = -Isrc -isystem third_party
LDFLAGS  += -pthread

BUILD = build

.PHONY: all server test run clean

all: server

$(BUILD):
	mkdir -p $(BUILD)

server: $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) src/main.cpp src/analyzer.cpp -o $(BUILD)/scamshield-server $(LDFLAGS)

test: $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) tests/test_analyzer.cpp src/analyzer.cpp -o $(BUILD)/test-analyzer
	./$(BUILD)/test-analyzer

run: server
	./$(BUILD)/scamshield-server

clean:
	rm -rf $(BUILD)
