CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c99 -D_DEFAULT_SOURCE -Iinclude
TARGET = cyber

# add the parser source here:
SRCS = src/main.c src/capture.c src/parser.c src/parser_log.c src/rules_stateless.c src/rules_stateful.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lpcap

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
.PHONY: all clean
