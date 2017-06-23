# Copyright © 2017 Jakub Wilk <jwilk@jwilk.net>
# SPDX-License-Identifier: MIT

CFLAGS ?= -g -O2
CFLAGS += -Wall -Wextra -Wconversion
LDLIBS = -lgcrypt -lgpg-error

prog = nistp256-keygen

.PHONY: all
all: $(prog)

.PHONY: clean
clean:
	rm -f $(prog)

# vim:ts=4 sts=4 sw=4 noet
