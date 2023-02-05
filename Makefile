# compiler
CC := gcc
RUNSTATEDIR ?= /var/run
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
DESTDIR ?= bin
SYSCONFDIR ?= /etc
CFLAGS ?= -O3
CFLAGS += -std=gnu99 -D_GNU_SOURCE
CFLAGS += -g -Wall -Wextra
CFLAGS += -MMD -MP
CFLAGS += -DRUNSTATEDIR="\"$(RUNSTATEDIR)\""

TARGET := c-template 
SRCS := main.c

build:  
	$(CC) $(CFLAGS) -o $(DESTDIR)/$(TARGET) $(SRCS)

run:
	$(OUTPUT_DIR)/$(TARGET)

clean: 
	$(RM) $(OUTPUT_DIR)/$(TARGET)
