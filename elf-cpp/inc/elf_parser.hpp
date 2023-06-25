
#ifndef ELF_PARSE_H
#define ELF_PARSE_H


#include <fstream>
#include <filesystem>
#include <iterator>
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <map>
#include <cmath>

namespace elf {

// elf header
constexpr int EI_MAG_offset =		0x00;
constexpr int EI_CLASS_offset =   	0x04;
constexpr int EI_DATA_offset =    	0x05;
constexpr int EI_VERSION_offset = 	0x06;
constexpr int EI_OSABI_offset =   	0x07;
constexpr int EI_ABIVERSION_offset =	0x08;
constexpr int EI_PAD_offset = 		0x09;
constexpr int e_type_offset = 		0x10;
constexpr int e_machine_offset =  	0x12;
constexpr int e_version_offset =  	0x14;
constexpr int e_entry_offset =    	0x18;
constexpr int e_phoff_32_offset = 	0x1C;
constexpr int e_phoff_64_offset = 	0x20;
constexpr int e_shoff_32_offset = 	0x20;
constexpr int e_shoff_64_offset = 	0x28;
constexpr int e_flags_32_offset = 	0x24;
constexpr int e_flags_64_offset = 	0x30;
constexpr int e_ehsize_32_offset =    	0x28;
constexpr int e_ehsize_64_offset =    	0x34;
constexpr int e_phentsize_32_offset = 	0x2A;
constexpr int e_phentsize_64_offset = 	0x36;
constexpr int e_phnum_32_offset = 	0x2C;
constexpr int e_phnum_64_offset = 	0x38;
constexpr int e_shentsize_32_offset = 	0x2E;
constexpr int e_shentsize_64_offset = 	0x3A;
constexpr int e_shnum_32_offset = 	0x30;
constexpr int e_shnum_64_offset = 	0x3C;
constexpr int e_shstrndx_32_offset =  	0x32;
constexpr int e_shstrndx_64_offset =  	0x3E;

constexpr int EI_MAG_size = 		4;
constexpr int EI_CLASS_size = 		1;
constexpr int EI_DATA_size = 		1;
constexpr int EI_VERSION_size = 	1;
constexpr int EI_OSABI_size = 		1;
constexpr int EI_ABIVERSION_size = 	1;
constexpr int EI_PAD_size = 		7;
constexpr int e_type_size = 		2;
constexpr int e_machine_size = 		2;
constexpr int e_version_size = 		4;
constexpr int e_entry_32_size = 	4;
constexpr int e_entry_64_size = 	8;
constexpr int e_phoff_32_size = 	4;
constexpr int e_phoff_64_size = 	8;
constexpr int e_shoff_32_size = 	4;
constexpr int e_shoff_64_size = 	8;
constexpr int e_flags_size = 		4;
constexpr int e_ehsize_size = 		2;
constexpr int e_phentsize_size = 	2;
constexpr int e_phnum_size = 		2;
constexpr int e_shentsize_size = 	2;
constexpr int e_shnum_size = 		2;
constexpr int e_shstrndx_size = 	2;

// Program Header
constexpr int p_type_offset =		0x00;
constexpr int p_flags_32_offset =	0x18;
constexpr int p_flags_64_offset =	0x04;
constexpr int p_offset_32_offset =	0x04;
constexpr int p_offset_64_offset = 	0x08;
constexpr int p_vaddr_32_offset = 	0x08;
constexpr int p_vaddr_64_offset = 	0x10;
constexpr int p_paddr_32_offset = 	0x0C;
constexpr int p_paddr_64_offset = 	0x18;
constexpr int p_filesz_32_offset = 	0x10;
constexpr int p_filesz_64_offset = 	0x20;
constexpr int p_memsz_32_offset = 	0x14;
constexpr int p_memsz_64_offset = 	0x28;
constexpr int p_align_32_offset = 	0x1C;
constexpr int p_align_64_offset = 	0x30;

constexpr int p_type_size =		4;
constexpr int p_flags_size =		4;
constexpr int p_offset_32_size =	4;
constexpr int p_offset_64_size =	8;
constexpr int p_vaddr_32_size =		4;
constexpr int p_vaddr_64_size =		8;
constexpr int p_paddr_32_size =		4;
constexpr int p_paddr_64_size =		8;
constexpr int p_filesz_32_size =	4;
constexpr int p_filesz_64_size =	8;
constexpr int p_memsz_32_size =		4;
constexpr int p_memsz_64_size =		8;
constexpr int p_align_32_size =		4;
constexpr int p_align_64_size =		8;

// Section Header
constexpr int sh_name_offset =		0x00;
constexpr int sh_type_offset =		0x04;
constexpr int sh_flags_offset =		0x08;
constexpr int sh_addr_32_offset =	0x0C;
constexpr int sh_addr_64_offset =	0x10;
constexpr int sh_offset_32_offset =	0x10;
constexpr int sh_offset_64_offset =	0x18;
constexpr int sh_size_32_offset =	0x14;
constexpr int sh_size_64_offset =	0x20;
constexpr int sh_link_32_offset =	0x18;
constexpr int sh_link_64_offset =	0x28;
constexpr int sh_info_32_offset =	0x1C;
constexpr int sh_info_64_offset =	0x2C;
constexpr int sh_addralign_32_offset =	0x20;
constexpr int sh_addralign_64_offset =	0x30;
constexpr int sh_entsize_32_offset =	0x24;
constexpr int sh_entsize_64_offset =	0x38;

constexpr int sh_name_size =		4;
constexpr int sh_type_size =		4;
constexpr int sh_flags_32_size =	4;
constexpr int sh_flags_64_size =	8;
constexpr int sh_addr_32_size =		4;
constexpr int sh_addr_64_size =		8;
constexpr int sh_offset_32_size =	4;
constexpr int sh_offset_64_size =	8;
constexpr int sh_size_32_size =		4;
constexpr int sh_size_64_size =		8;
constexpr int sh_link_size =		4;
constexpr int sh_info_size =		4;
constexpr int sh_addralign_32_size =	4;
constexpr int sh_addralign_64_size =	8;
constexpr int sh_entsize_32_size =	4;
constexpr int sh_entsize_64_size =	8;

typedef std::uint32_t Elf32_Addr;
typedef std::uint16_t Elf32_Half;
typedef std::uint32_t Elf32_Off;
typedef std::int32_t Elf32_Sword;
typedef std::uint32_t Elf32_Word;

typedef std::uint64_t Elf64_Addr;
typedef std::uint16_t Elf64_Half;
typedef std::uint64_t Elf64_Off;
typedef std::int64_t Elf64_Sword;
typedef std::uint32_t Elf64_Word;
typedef std::uint64_t Elf64_Xword;

typedef struct e_ident_t {

	std::uint8_t EI_OSABI;
	std::uint8_t EI_ABIVERSION;
} e_ident_t;

typedef struct elf32Header_t {
	std::vector<uint8_t> e_ident;
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
} elf32Header_t;

typedef struct elf64Header_t {
	std::vector<uint8_t> e_ident;
        Elf64_Half e_type;
        Elf64_Half e_machine;
        Elf64_Word e_version;
        Elf64_Addr e_entry;
        Elf64_Off e_phoff;
        Elf64_Off e_shoff;
        Elf64_Word e_flags;
        Elf64_Half e_ehsize;
        Elf64_Half e_phentsize;
        Elf64_Half e_phnum;
        Elf64_Half e_shentsize;
        Elf64_Half e_shnum;
        Elf64_Half e_shstrndx;
} elf64Header_t;

typedef struct programHeader32_t {
	Elf32_Word p_type;
	Elf32_Off p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
} programHeader32_t;

typedef struct programHeader64_t {
        Elf64_Word p_type;
        Elf64_Off p_offset;
        Elf64_Addr p_vaddr;
        Elf64_Addr p_paddr;
        Elf64_Xword p_filesz;
        Elf64_Xword p_memsz;
        Elf64_Word p_flags;
        Elf64_Xword p_align;
} programHeader64_t;

typedef struct segment32_t : programHeader32_t {
	std::vector<int> sectionMapIndexes;
} segment32_t;

typedef struct segment64_t : programHeader64_t {
	std::vector<int> sectionMapIndexes;
} segment64_t;

typedef struct sectionHeader32_t {
	Elf32_Word sh_name;
	Elf32_Word sh_type;
	Elf32_Word sh_flags;
	Elf32_Addr sh_addr;
	Elf32_Off sh_offset;
	Elf32_Word sh_size;
	Elf32_Word sh_link;
	Elf32_Word sh_info;
	Elf32_Word sh_addralign;
	Elf32_Word sh_entsize;
} sectionHeader32_t;

typedef struct sectionHeader64_t {
	Elf64_Word sh_name;
        Elf64_Word sh_type;
        Elf64_Xword sh_flags;
        Elf64_Addr sh_addr;
        Elf64_Off sh_offset;
        Elf64_Xword sh_size;
        Elf64_Word sh_link;
        Elf64_Word sh_info;
        Elf64_Xword sh_addralign;
        Elf64_Xword sh_entsize;
} sectionHaeder64_t;

typedef struct section32_t : sectionHeader32_t {
	std::string name;
	std::vector<std::uint8_t> bytes;
} section32_t;

typedef struct section64_t : sectionHeader64_t {
	std::string name;
	std::vector<std::uint8_t> bytes;
} section64_t;


bool compare_section_32(const section32_t& a, const section32_t& b);
bool compare_segments_32(const segment32_t& a, const segment32_t& b);


class elf_parser {

	// Factory
	public:
		static elf_parser* read_file(std::string file);
		virtual std::vector<std::uint8_t> read_section(std::string name) = 0;
		virtual void print_elf_header(void) = 0;
		virtual void print_sections(void) = 0;
		virtual void print_segments(void) = 0;
		virtual void print_symbol_table(void) = 0;

	protected:
		unsigned int join_bytes(std::vector<std::uint8_t>::iterator ptr, int numOfBytes, bool bigEndian);
		virtual std::vector<int> map_sections_to_segments(std::uint32_t offset,
                        std::uint32_t size, std::vector<int> result=std::vector<int>(), int index=0) = 0;
		std::map<std::uint8_t, std::string> EI_OSABI {
			{0x00, "System V"}, {0x01, "HP-UX"}, {0x02, "NetBSD"}, {0x03, "Linux"}, {0x04, "GNU Hurd"},
			{0x06, "Solaris"}, {0x07, "AIX (Monterey)"}, {0x08, "IRIX"}, {0x09, "FreeBSD"},
			{0x0A, "Tru64"}, {0x0B, "Novell Modesto"}, {0x0C, "OpenBSD"}, {0x0D, "OpenVMS"},
			{0x0E, "NonStop Kernel"}, {0x0F, "AROS"}, {0x10, "FenixOS"}, {0x11, "Nuxi CloudABI"},
			{0x12, "Stratus Technologies OpenVOS"}
		};
		std::map<std::uint16_t, std::string> e_type {
			{0x00, "NONE"}, {0x01, "REL"}, {0x02, "EXEC"}, {0x03, "DYN"}, {0x04, "CORE"},
			{0xFE00, "LOOS"}, {0xFEFF, "HIOS"}, {0xFF00, "LOPROC"}, {0xFFFF, "HIPROC"}
		};
		std::map<std::uint16_t, std::string> e_machine {
			{0x00, "No specific instruction set"}, {0x01, "AT&T WE 32100"}, {0x02, "SPARC"},
			{0x03, "x86"}, {0x04, "Motorola 68000 (M68k)"}, {0x05, "Motorola 88000 (M88k)"},
			{0x06, "Intel MCU"}, {0x07, "Intel 80860"}, {0x08, "MIPS"}, {0x09, "IBM System/370"},
			{0x0A, "MIPS RS3000 Little-endian"}, {0x0F, "Hewlett-Packard PA-RISC"},
			{0x13, "Intel 80960"}, {0x14, "PowerPC"}, {0x15, "PowerPC (64-bit)"},
			{0x16, "S390, including S390x"}, {0x17, "IBM SPU/SPC"}, {0x24, "NEC V800"},
			{0x25, "Fujitsu FR20"}, {0x26, "TRW RH-32"}, {0x27, "Motorola RCE"},
			{0x28, "Arm (up to Armv7/AArch32)"}, {0x29, "Digital Alpha"}, {0x2A, "SuperH"},
			{0x2B, "SPARC Version 9"}, {0x2C, "Siemens TriCore embedded processor"},
			{0x2D, "Argonaut RISC Core"}, {0x2E, "Hitachi H8/300"}, {0x2F, "Hitachi H8/300H"},
			{0x30, "Hitachi H8S"}, {0x31, "Hitachi H8/500"}, {0x32, "IA-64"}, {0x33, "Stanford MIPS-X"},
			{0x34, "Motorola ColdFire"}, {0x35, "Motorola M68HC12"},
			{0x36, "Fujitsu MMA Multimedia Accelerator"}, {0x37, "Siemens PCP"},
			{0x38, "Sony nCPU embedded RISC processor"}, {0x39, "Denso NDR1 microprocessor"},
			{0x3A, "Motorola Star*Core processor"}, {0x3B, "Toyota ME16 processor"},
			{0x3C, "STMicroelectronics ST100 processor"},
			{0x3D, "Advanced Logic Corp. TinyJ embedded processor family"}, {0x3E, "AMD x86-64"},
			{0x3F, "Sony DSP Processor"}, {0x40, "Digital Equipment Corp. PDP-10"},
			{0x41, "Digital Equipment Corp. PDP-11"}, {0x42, "Siemens FX66 microcontroller"},
			{0x43, "STMicroelectronics ST9+ 8/16 bit microcontroller"},
			{0x44, "STMicroelectronics ST7 8-bit microcontroller"},
			{0x45, "Motorola MC68HC16 Microcontroller"}, {0x46, "Motorola MC68HC11 Microcontroller"},
			{0x47, "Motorola MC68HC08 Microcontroller"}, {0x48, "Motorola MC68HC05 Microcontroller"},
			{0x49, "Silicon Graphics SVx"}, {0x4A, "STMicroelectronics ST19 8-bit microcontroller"},
			{0x4B, "Digital VAX"}, {0x4C, "Axis Communications 32-bit embedded processor"},
			{0x4D, "Infineon Technologies 32-bit embedded processor"},
			{0x4E, "Element 14 64-bit DSP Processor"}, {0x4F, "LSI Logic 16-bit DSP Processor"},
			{0x8C, "TMS320C6000 Family"}, {0xAF, "MCST Elbrus e2k"},
			{0xB7, "Arm 64-bits (Armv8/AArch64)"}, {0xDC, "Zilog Z80"}, {0xF3, "RISC-V"},
			{0xF7, "Berkeley Packet Filter"}, {0x101, "WDC 65C816"}
		};
		std::map<std::uint32_t, std::string> programType {
			{0x00, "NULL"}, {0x01, "LOAD"}, {0x02, "DYNAMIC"}, {0x03, "INTERP"},
			{0x04, "NOTE"}, {0x05, "SHLIB"}, {0x06, "PHDR"}, {0x07, "TLS"},
			{0x60000000, "LOOS"}, {0x6FFFFFFF, "HIOS"}, {0x70000000, "LOPROC"},
			{0x7FFFFFFF, "HIPROC"},
		};
		 std::map<std::uint32_t, std::vector<std::string>> programFlags {
			 {0x1, {"Executable", "E"}}, {0x2, {"Writable", "W"}}, {0x4, {"Readable", "R"}}
		};
		std::map<std::uint32_t, std::string> sectionType {
			{0x00,  "NULL"}, {0x01,  "PROGBITS"}, {0x02,  "SYMTAB"}, {0x03,  "STRTAB"},
			{0x04,  "RELA"}, {0x05,  "HASH"}, {0x06,  "DYNAMIC"}, {0x07,  "NOTE"}, {0x08,  "NOBITS"},
			{0x09,  "REL"}, {0x0A,  "SHLIB"}, {0x0B,  "DYNSYM"}, {0x0E,  "INIT_ARRAY"},
			{0x0F,  "FINI_ARRAY"}, {0x10,  "PREINIT_ARRAY"}, {0x11,  "GROUP"},
			{0x12,  "SYMTAB_SHNDX"}, {0x13,  "NUM"}, {0x60000000, "LOOS"}
                };
		std::map<std::uint32_t, std::vector<std::string>> sectionFlags {
			{0x01, {"SHF_WRITE", "W"}}, {0x02, {"SHF_ALLOC", "A"}}, {0x04, {"SHF_EXECINSTR", "X"}},
			{0x10, {"SHF_MERGE", "M"}}, {0x20, {"SHF_STRINGS", "S"}}, {0x40, {"SHF_INFO_LINK", "I"}},
			{0x80, {"SHF_LINK_ORDER", "L"}}, {0x100, {"SHF_OS_NONCONFORMING", "O"}},
			{0x200, {"SHF_GROUP", "G"}}, {0x400, {"SHF_TLS", "T"}}, {0x0FF00000, {"SHF_MASKOS", "o"}},
			{0xF0000000, {"SHF_MASKPROC", "p"}}, {0x4000000, {"SHF_ORDERED", ""}},
			{0x8000000, {"SHF_EXCLUDE", ""}}
		};
};


class elf_32_parser : public elf_parser {

	private:
                elf32Header_t elfHeader;
		std::vector<segment32_t> programHeaderTable;
                std::vector<section32_t> sectionHeaderTable;
		std::vector<int> map_sections_to_segments(std::uint32_t offset,
                        std::uint32_t size, std::vector<int> result=std::vector<int>({}), int index=0) override;

	public:
		elf_32_parser(std::vector<std::uint8_t> bytes);
		std::vector<std::uint8_t> read_section(std::string name) override;
		void print_elf_header(void) override;
		void print_sections(void) override;
		void print_segments(void) override;
		void print_symbol_table(void) override;
};


class elf_64_parser : public elf_parser {

	private:
                elf64Header_t elfHeader;
		std::vector<programHeader64_t> programHeaders;
                std::vector<sectionHeader64_t> sectionHeaderTable;
		std::vector<int> map_sections_to_segments(std::uint32_t offset,
                        std::uint32_t size, std::vector<int> result=std::vector<int>(), int index=0) override {return std::vector<int>();}

	public:
		elf_64_parser(std::vector<std::uint8_t> bytes);
		std::vector<std::uint8_t> read_section(std::string name) override {return std::vector<std::uint8_t>();}
		void print_elf_header(void) override {}
		void print_sections(void) override {}
		void print_segments(void) override {}
		void print_symbol_table(void) override {}
};


class elf_error : public elf_parser {
	// Factory error class (default return value if exception thrown)
	private:
		std::vector<int> map_sections_to_segments(uint32_t offset,
                        uint32_t size, std::vector<int> result=std::vector<int>(), int index=0) override {return std::vector<int>();}
	
	public:
		std::vector<std::uint8_t> read_section(std::string name) override {return std::vector<std::uint8_t>();}
                void print_elf_header(void) override {}
                void print_sections(void) override {}
		void print_segments(void) override {}
                void print_symbol_table(void) override {}
};


} // end of namespace elf

#endif
