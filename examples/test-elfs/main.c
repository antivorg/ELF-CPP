
static int bss[10];				// .bss
static int data[10] = {10};			// .data
static const char rodata[10] = {"string123"};	// .rodata

int main(void)
{
    int a=0, b=1;
    return a+b;
}

