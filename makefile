
CC = gcc 
LD = gcc

SOURCE_PATH  = source
INCLUDE_PATH = include

LIB_PATH     = lib
OBJ_PATH     = obj

CFLAGS      = -I$(INCLUDE_PATH) -std=c++11 -g -O3 -D_DEBUG_
LD_CFLAGES  = -lstdc++ -lpthread $(LIB_PATH)/libpcap.a

SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.cpp)
OBJ_FILES    = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

TARGET = dosAnalysis

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGES)
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.cpp
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_PATH) $(TARGET)
