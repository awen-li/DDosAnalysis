
CC = gcc 
LD = gcc

ANALYSIS_DIR = ../..

SOURCE_PATH  = source
INCLUDE_PATH = include

OBJ_PATH     = obj

CFLAGS      = -I$(INCLUDE_PATH) -I$(ANALYSIS_DIR)/include -std=c++11 -g 
LD_CFLAGES  = -lstdc++ -lpthread $(ANALYSIS_DIR)/lib/libpcap.a $(ANALYSIS_DIR)/lib/libiec61850.a

ANALYSIS_SOURCE = $(ANALYSIS_DIR)/source/Capture.cpp $(ANALYSIS_DIR)/source/Packet.cpp

SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.cpp) $(wildcard $(ANALYSIS_SOURCE))
OBJ_FILES    = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

TARGET = gsattack

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGES)
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.cpp
	@cp $(ANALYSIS_SOURCE) $(SOURCE_PATH)/
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_PATH) $(TARGET)

