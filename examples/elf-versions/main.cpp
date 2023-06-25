#include "../../elf-cpp/inc/elf_parser.hpp"

#define SHOW_UBUNTU
#define SHOW_MIPS

#define SHOW_SECTS_SEGS

int main(void) {

	elf::elf_parser* elfFac;

	#ifdef SHOW_UBUNTU
	// gcc (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0
        //auto elfFile = elfFac->read_file(file);
	//elfFile->
	#endif

	#ifdef SHOW_MIPS
	// mips-linux-gnu-gcc (Ubuntu 10.3.0-1ubuntu1) 10.3.0
	auto elfFile = elfFac->read_file("../test-elfs/gcc-mips-linux.out");
	//elfFile->print_elf_header();
	#ifdef SHOW_SECTS_SEGS
	elfFile->print_sections();
	elfFile->print_segments();
	#endif
	delete elfFile;
	#endif

	return 1;
}
