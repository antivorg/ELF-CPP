# sudo apt install gcc gcc-mips-linux-gnu gcc-arm-none-eabi

all:
	gcc main.c -o gcc-ubuntu.out
	mips-linux-gnu-gcc main.c -o gcc-mips-linux.out
	arm-none-eabi-gcc --specs=nosys.specs main.c -o gcc-arm-linux.out

clean:
	rm *.out

