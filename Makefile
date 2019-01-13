# Sources
SRC_DIR = .
OBJS = $(foreach dir,$(SRC_DIR),$(subst .c,.o,$(wildcard $(dir)/*.c))) $(foreach dir,$(SRC_DIR),$(subst .cpp,.o,$(wildcard $(dir)/*.cpp)))

# Compiler Settings
OUTPUT = nrooooooo
CXXFLAGS = -Wall -g -I. -std=c++17
CFLAGS = -I. -std=gnu11
# If this fails, use "-pthread" instead of "-lpthread"
LIBS = -lpthread -lunicorn -lstdc++fs
CC = gcc
# Note: requires a g++ that supports the -std=c++17 flag, if g++ in your path doesn't support
#       C++17, update your g++ and possibly edit this to match the right version of g++
# Example:
# CXX = g++8
CXX = g++
ifeq ($(OS),Windows_NT)
    #Windows Build CFG
    CFLAGS += 
    LIBS += 
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        # OS X
        CFLAGS +=
        LIBS += 
    else
        # Linux
        CFLAGS += 
        CXXFLAGS += 
        LIBS += 
    endif
endif

main: $(OBJS)
	$(CXX) -o $(OUTPUT) $(OBJS) $(LIBS)

clean:
	rm -rf $(OUTPUT) $(OUTPUT).exe $(OBJS)
