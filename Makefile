# Makefile for building the git-crypt project
BINARY_NAME = git-crypt
BUILD_DIR = build

.PHONY: all clean build

all: clean build

clean:
	rm -rf $(BUILD_DIR)

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME)
