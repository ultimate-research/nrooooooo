# Sources
SRC_DIR = . mmio
OBJS = $(foreach dir,$(SRC_DIR),$(subst .c,.o,$(wildcard $(dir)/*.c))) $(foreach dir,$(SRC_DIR),$(subst .cpp,.o,$(wildcard $(dir)/*.cpp)))

# Compiler Settings
OUTPUT = nrooooooo
CXXFLAGS = -Wall -g -I. -std=c++17
CFLAGS = -I. -std=gnu11
LIBS = -lpthread -lunicorn -liberty -lstdc++fs
CC = gcc
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
