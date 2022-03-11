CC = g++
LIBFLAGS = $(shell pkg-config --libs botan-2)
CPPFLAGS = -g -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -O3 $(shell pkg-config --cflags botan-2)
DEPS = Encryption.hpp
OBJ = main.o Encryption.o
TARGET = EncryptionWrapper

%.o:%.c $(DEPS)
	$(CC) -c -o $@ $< $(CPPFLAGS) $(LIBFLAGS)

$(TARGET): $(OBJ)
	$(CC) $(CPPFLAGS) -o $@ $^ $(LIBFLAGS)

clean:
	rm $(TARGET) $(OBJ) 
	
help:
	@echo	"Usage: make [target] ../n"
	@echo	"Miscellaneous:"
	@echo	"help\t\t\tShows this help\n"
	@echo	"Build:"
	@echo	"all\t\t\tBuild all the project\n"
	@echo	"Cleaning:"
	@echo	"clean\t\t\tRemove all intermediate objects"
