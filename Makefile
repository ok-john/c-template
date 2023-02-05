# compiler
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS = -g -Wall

# output name & dir
TARGET = fish
OUTPUT_DIR = ./bin

# space seperated list of c source files
SRCS = main.c

build:  
	$(CC) $(CFLAGS) -o $(OUTPUT_DIR)/$(TARGET) $(SRCS)

run:
	$(OUTPUT_DIR)/$(TARGET)

clean: 
	$(RM) $(OUTPUT_DIR)/$(TARGET)
