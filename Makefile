all:
	gcc ./src/*.c

debug:
	gcc -g3 -DDEBUG ./src/*.c

preprocess:
	gcc -E ./src/dhcp_options.h -o a.pre

clean:
	rm -f ./a.out ./a.pre
