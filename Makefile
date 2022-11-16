all: test

test: test.c gost.c
	gcc test.c gost.c -o test

clean: 
	rm test
