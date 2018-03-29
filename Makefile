DEMO = md5
PWD := $(shell pwd)

SRCS = $(wildcard *.c)

all:
	@gcc $(SRCS) -o $(DEMO) -I $(PWD)

clean:
	@rm -f $(OBJS) $(DEMO)

.PHONY: all clean
