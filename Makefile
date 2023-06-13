TARGET_EXEC := khazad_dum

CXX := g++
CXXFLAGS += -Wall -Werror -Wextra -std=c++17
CXXFLAGS += -I./include
LDFLAGS   = -L=/usr/local/lib -ltss2-esys

BUILD_DIR := ./build
SRC_DIRS := ./src

SRCS := $(shell find $(SRC_DIRS) -name '*.cpp')
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

$(info $(SRCS))
$(info $(OBJS))

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CXX) $(LDFLAGS) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.cpp.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf bin/*.o