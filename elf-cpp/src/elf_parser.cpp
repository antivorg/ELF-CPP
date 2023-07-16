#include "../inc/elf_parser.hpp"


namespace elf {


bool compare_sections_32(const section32_t& a, const section32_t& b) {

        return a.sh_offset < b.sh_offset ?
				true : (a.sh_offset == b.sh_offset ?
						a.sh_size > b.sh_size : false);
}


//bool compare_segments_32(const segment32_t& a, const segment32_t& b) {

//	return a.
//}


elf_parser* elf_parser::read_file(std::string file) {

	try {
		std::vector<std::uint8_t> bytes;
		if (std::filesystem::exists(file)) {
			std::ifstream fileIt(file, std::ios::binary);
        		bytes = std::vector<std::uint8_t>(
					(std::istreambuf_iterator<char>(fileIt)),
					(std::istreambuf_iterator<char>()));
        		fileIt.close();
		} else {
			throw 0;
		}

		if (bytes[0] != 0x7F || bytes[1] != 0x45
				|| bytes[2] != 0x4c || bytes[3] != 0x46) {
			throw 1;
		}

		if (bytes[EI_CLASS_offset] == 1) {
                	// 32-bit format
                	return new elf_32_parser(bytes);
        	} else if (bytes[EI_CLASS_offset] == 2) {
                	// 64-bit format
                	return new elf_64_parser(bytes);
        	} else {
			throw 2;
		}
	}
 	catch (int e) {
		switch(e) {
			case 0:
				std::cout << "Exception: File doesn't exist"
						<< std::endl;
				break;
			case 1:
				std::cout << "Exception: Incorrect magic number"
						" for ELF format" << std::endl;
				break;
			case 2:
				std::cout << "Exception: Unexpected value in ELF"
						" header" << std::endl;
				break;
		}
	return new elf_error();
	}
}


unsigned int elf_parser::join_bytes(std::vector<std::uint8_t>::iterator ptr,
					int numOfBytes, bool bigEndian) {

	unsigned int result = 0;
	for (int i=0; i<numOfBytes; i++) {
		if (bigEndian) {
			result = result << 8;
			result += (std::uint8_t) *ptr;
		} else {
			result += ((std::uint8_t) *ptr) << (8*i);
        	}
        	ptr++;
	}
	return result;
}


elf_32_parser::elf_32_parser(std::vector<std::uint8_t> bytes) {

	// parse file header
	for (int i=0; i<10; i++) elfHeader.e_ident.push_back(bytes[i]);
	bool bigEndian = bytes[EI_DATA_offset] == 2;
	elfHeader.e_type = 	join_bytes(bytes.begin()+e_type_offset,
						e_type_size, bigEndian);
	elfHeader.e_machine = 	join_bytes(bytes.begin()+e_machine_offset,
						e_machine_size, bigEndian);
	elfHeader.e_version = 	join_bytes(bytes.begin()+e_version_offset,
						e_version_size, bigEndian);
	elfHeader.e_entry = 	join_bytes(bytes.begin()+e_entry_offset,
						e_entry_32_size, bigEndian);
	elfHeader.e_phoff = 	join_bytes(bytes.begin()+e_phoff_32_offset, 
						e_phoff_32_size, bigEndian);
	elfHeader.e_shoff = 	join_bytes(bytes.begin()+e_shoff_32_offset,
						e_shoff_32_size, bigEndian);
	elfHeader.e_flags = 	join_bytes(bytes.begin()+e_flags_32_offset,
						e_flags_size, bigEndian);
	elfHeader.e_ehsize = 	join_bytes(bytes.begin()+e_ehsize_32_offset,
						e_ehsize_size, bigEndian);
	elfHeader.e_phentsize = join_bytes(bytes.begin()+e_phentsize_32_offset,
						e_phentsize_size, bigEndian);
	elfHeader.e_phnum = 	join_bytes(bytes.begin()+e_phnum_32_offset,
						e_phnum_size, bigEndian);
	elfHeader.e_shentsize = join_bytes(bytes.begin()+e_shentsize_32_offset,
						e_shentsize_size, bigEndian);
	elfHeader.e_shnum = 	join_bytes(bytes.begin()+e_shnum_32_offset,
						e_shnum_size, bigEndian);
	elfHeader.e_shstrndx = 	join_bytes(bytes.begin()+e_shstrndx_32_offset,
						e_shstrndx_size, bigEndian);

	// parse section header
	for (int i=0; i<elfHeader.e_shnum; i++) {
		int offset = elfHeader.e_shoff + elfHeader.e_shentsize * i;
		section32_t header;
		header.sh_name = 	join_bytes(bytes.begin()+offset+sh_name_offset,
							sh_name_size, bigEndian);
		header.sh_type = 	join_bytes(bytes.begin()+offset+sh_type_offset,
							sh_type_size, bigEndian);
		header.sh_flags = 	join_bytes(bytes.begin()+offset+sh_flags_offset,
							sh_flags_32_size, bigEndian);
		header.sh_addr = 	join_bytes(bytes.begin()+offset+sh_addr_32_offset,
							sh_addr_32_size, bigEndian);
		header.sh_offset = 	join_bytes(bytes.begin()+offset+sh_offset_32_offset,
							sh_offset_32_size, bigEndian);
		header.sh_size = 	join_bytes(bytes.begin()+offset+sh_size_32_offset,
							sh_size_32_size, bigEndian);
		header.sh_link = 	join_bytes(bytes.begin()+offset+sh_link_32_offset,
							sh_link_size, bigEndian);
		header.sh_info = 	join_bytes(bytes.begin()+offset+sh_info_32_offset,
							sh_info_size, bigEndian);
		header.sh_addralign = 	join_bytes(bytes.begin()+offset+sh_addralign_32_offset,
							sh_addralign_32_size, bigEndian);
		header.sh_entsize = 	join_bytes(bytes.begin()+offset+sh_entsize_32_offset,
							sh_entsize_32_size, bigEndian);
		for (int i=header.sh_offset; i-header.sh_offset<header.sh_size; i++) {
			header.bytes.push_back(bytes[i]);
		}
		sectionHeaderTable.push_back(header);
	}

	// parser string table
	sectionHeader32_t stringTableHeader = sectionHeaderTable[elfHeader.e_shstrndx];
	for (section32_t &section : sectionHeaderTable) {
		if (section.sh_type == 0x00) {
			continue;
		}
		int offset = stringTableHeader.sh_offset + section.sh_name;
		std::string sectionName = "";
		while (bytes[offset] != '\0') {
			sectionName += bytes[offset];
			offset++;
		}
		section.name = sectionName;
	}

	// parse program headers
	for (int i=0; i<elfHeader.e_phnum; i++) {
		int offset = elfHeader.e_phoff + elfHeader.e_phentsize * i;
		segment32_t header;
		header.p_type =		join_bytes(bytes.begin()+offset+p_type_offset,
							p_type_size, bigEndian);
		header.p_offset = 	join_bytes(bytes.begin()+offset+p_offset_32_offset,
							p_offset_32_size, bigEndian);
		header.p_vaddr = 	join_bytes(bytes.begin()+offset+p_vaddr_32_offset,
							p_vaddr_32_size, bigEndian);
		header.p_paddr = 	join_bytes(bytes.begin()+offset+p_paddr_32_offset,
							p_paddr_32_size, bigEndian);
		header.p_filesz = 	join_bytes(bytes.begin()+offset+p_filesz_32_offset,
							p_filesz_32_size, bigEndian);
		header.p_memsz = 	join_bytes(bytes.begin()+offset+p_memsz_32_offset,
							p_memsz_32_size, bigEndian);
		header.p_flags = 	join_bytes(bytes.begin()+offset+p_flags_32_offset,
							p_flags_size, bigEndian);
		header.p_align = 	join_bytes(bytes.begin()+offset+p_align_32_offset,
							p_align_32_size, bigEndian);
		header.sectionMapIndexes = map_sections_to_segments(header.p_offset,
									header.p_filesz);
		programHeaderTable.push_back(header);
	}
}


std::vector<int> elf_32_parser::map_sections_to_segments(std::uint32_t offset,
			std::uint32_t size, std::vector<int> result, int index) {

	std::cout << "rec: " << size << '\t' << offset << std::endl;
	// recursive
	if (size == 0) {
		std::cout << " correct " << std::endl;
		return result;
	}
	int closestIndex = sectionHeaderTable.size()-1;
	for (int i=index; i<sectionHeaderTable.size(); i++) {
		if (sectionHeaderTable[i].sh_offset == offset) {
			std::cout << "sec: " << sectionHeaderTable[i].sh_size;
			std::cout << '\t' << sectionHeaderTable[i].sh_offset << std::endl;
			std::cout << sectionHeaderTable[i].name << std::endl;
			result.push_back(i);
			if (sectionHeaderTable[i].sh_size == 0) {
				std::cout << "zero" << std::endl;
				continue;
			}
			return result = map_sections_to_segments(
				offset+sectionHeaderTable[i].sh_size,
				size-sectionHeaderTable[i].sh_size, result, i+1);
		} else if (sectionHeaderTable[i].sh_offset > offset
				&& sectionHeaderTable[i].sh_offset
				< sectionHeaderTable[closestIndex].sh_offset) {
			closestIndex = i;
		}
	}
	//No contiguous match, check closest
	if (sectionHeaderTable[closestIndex].sh_offset < offset+size) {
		std::cout << "dec: " << sectionHeaderTable[closestIndex].name << std::endl;
		result.push_back(closestIndex);
		return result = map_sections_to_segments(
				sectionHeaderTable[closestIndex].sh_offset+sectionHeaderTable[closestIndex].sh_size,
				size-sectionHeaderTable[closestIndex].sh_size
					-(sectionHeaderTable[closestIndex].sh_offset-offset)
						, result, closestIndex+1);
	}
       	// EOF
	std::cout << " incorrect " << std::endl;
	return result;
}


std::vector<std::uint8_t> elf_32_parser::read_section(std::string name) {

	section32_t section;
	for (section32_t sectionHeader : sectionHeaderTable) {
		if (sectionHeader.name == name) {
			section = sectionHeader;
		}
	}

	return section.bytes;
}

void elf_32_parser::print_elf_header(void) {

	std::cout << std::left << "Magic Number: " << std::setfill('0')
								<< std::right;
	for (int i=0; i<10; i++) std::cout << std::setw(2) << std::hex
					<< (unsigned int) elfHeader.e_ident[i]
					<< " ";
	std::cout << std::endl << std::left << std::setfill(' ');
	std::cout << std::setw(36) << "Class:" << "ELF32" << std::endl;
	std::cout << std::setw(36) << "Data:";
	if (elfHeader.e_ident[EI_DATA_offset] - 1) {
		std::cout << "Big Endian";
	} else {
		std::cout << "Little Endian";
	}
	std::cout << std::endl << std::setw(36) << "Version:";
	if (elfHeader.e_ident[EI_VERSION_offset] == 1) {
		std::cout << "1 (current)";
	} else {
		std::cout << elfHeader.e_ident[EI_VERSION_offset];
	}
	std::cout << std::endl << std::setw(36) << "OS/ABI:";
	std::cout << EI_OSABI[elfHeader.e_ident[EI_OSABI_offset]] << std::endl;
	std::cout << std::setw(36) << "ABI Version";
	std::cout << (int) elfHeader.e_ident[EI_ABIVERSION_offset];
	std::cout << std::endl << std::setw(36) << "Type:";
	std::cout << e_type[elfHeader.e_type] << std::endl;
	std::cout << std::setw(36) << "Machine:";
	std::cout << e_machine[elfHeader.e_machine] << std::endl;
	std::cout << std::setw(36) << "Version:" << "0x" << std::hex;
	std::cout << (int) elfHeader.e_ident[EI_VERSION_offset];
	std::cout << std::endl << std::setw(36) << "Entry point address:";
	std::cout << "0x" << std::hex << elfHeader.e_entry;
	std::cout << std::endl << std::setw(36) << "Start of program headers:";
	std::cout << std::dec << (int) elfHeader.e_phoff;
	std::cout << std::endl << std::setw(36) << "Start of section headers:";
	std::cout << (int) elfHeader.e_shoff << std::endl;
	std::cout << std::setw(36) << "Flags:" << "0x" << std::hex;
	std::cout << (int) elfHeader.e_flags << std::endl;
	std::cout << std::setw(36) << "Size of this header:" << std::dec;
	std::cout << (int) elfHeader.e_ehsize << std::endl;
	std::cout << std::setw(36) << "Size of program headers:";
	std::cout << (int) elfHeader.e_phentsize << std::endl;
	std::cout << std::setw(36) << "Number of program headers:";
	std::cout << (int) elfHeader.e_phnum << std::endl;
	std::cout << std::setw(36) << "Size of section headers:";
	std::cout << (int) elfHeader.e_shentsize << std::endl;
	std::cout << std::setw(36) << "Number of section headers:";
	std::cout << (int) elfHeader.e_shnum << std::endl;
	std::cout << std::setw(36) << "Section header string table index:";
	std::cout << (int) elfHeader.e_shstrndx << std::endl;
}

void elf_32_parser::print_sections(void) {

	std::cout << std::left << std::setfill(' ') << std::setw(18) << "Name";
	std::cout << std::setw(15) << "Type";
	std::cout << std::setw(9) << "Addr";
	std::cout << std::setw(7) << "Off";
	std::cout << std::setw(7) << "Size";
	std::cout << "ES Flg Lk Inf Al";
	std::cout << std::endl;
	std::vector<section32_t> sections = sectionHeaderTable;
	std::sort(sections.begin(), sections.end(), compare_sections_32);
	for (section32_t section : sections) {
		std::cout << std::left << std::setfill(' ') << std::setw(18);
		std::cout << section.name << std::setw(15);
		std::cout << sectionType[section.sh_type] << std::right;
		std::cout << std::setfill('0') << std::setw(8) << std::hex;
		std::cout << section.sh_addr << ' ' << std::setw(6);
		std::cout << section.sh_offset << ' ' << std::setw(6);
		std::cout << section.sh_size << ' ' << std::setw(2) << std::hex;
		std::cout << section.sh_entsize << ' ';
		std::string flags = "";
		for (const auto &pair : sectionFlags) {
			if (!!(section.sh_flags & pair.first)) {
				flags += sectionFlags[pair.first][1];
			}
		}
		std::cout << std::setfill(' ') << std::setw(3) << flags << ' ';
		std::cout << std::setw(2) << std::dec << section.sh_link << ' ';
		std::cout << std::setw(3) << section.sh_info << ' ';
		std::cout << std::setw(2) << section.sh_addralign << std::endl;
	}
}


void elf_32_parser::print_segments(void) {

	//std::vector<segment32_t> segments = programHeaderTable;
        //std::sort(segments.begin(), segments.end(), compare_segments_32);

	// program headers
	std::cout << std::left << std::setfill(' ') << std::setw(15) << "Type";
	std::cout << std::setw(8) << "Offset" << std::setw(11) << "VirtAddr";
	std::cout << std::setw(11) << "PhysAddr" << std::setw(9) << "FileSiz";
	std::cout << std::setw(8) << "MemSiz" << std::setw(4) << "Flg Align";
	std::cout << std::endl;
	for (segment32_t segment : programHeaderTable) {
		std::cout << std::setfill(' ') << std::left << std::setw(15);
		std::cout << programType[segment.p_type] << std::setfill('0');
		std::cout << "0x" << std::setw(5) << std::right << std::hex;
		std::cout << segment.p_offset << " 0x" << std::setw(8);
		std::cout << segment.p_vaddr << " 0x" << std::setw(8);
		std::cout << segment.p_paddr << " 0x" << std::setw(6);
		std::cout << segment.p_filesz << " 0x" << std::setw(5);
		std::cout << segment.p_memsz << " ";
		std::string flag = "";
		for (const auto &pair : programFlags) {
                        if (!!(segment.p_flags & pair.first)) {
                                flag += programFlags[pair.first][1];
                        } else {
				flag += ' ';
			}
                }
		std::cout << flag << " 0x";
		std::cout << std::left << segment.p_align << std::endl;
	}

	// segment section map
	std::cout << std::endl;
	for (int i=0; i<programHeaderTable.size(); i++) {
		std::cout << std::dec << std::right
		<< std::setw(std::ceil(std::log10(programHeaderTable.size())));
		std::cout << i;
		for (int secHedIndex : programHeaderTable[i].sectionMapIndexes) {
			std::cout << ' ' << sectionHeaderTable[secHedIndex].name;
		}
		std::cout << std::endl;
	}
}


void elf_32_parser::print_symbol_table(void) {

	std::vector<std::uint8_t> bytes = read_section(".symtab");
	for (int i=1; i<bytes.size()+1; i++) {
		std::cout << std::right << std::setfill('0');
		std::cout << std::setw(2) << std::hex
				<< (unsigned int) bytes[i-1];
		if (i % 4 == 0) std::cout << " ";
		if (i % 16 == 0) std::cout << std::endl;
	}
	std::cout << std::endl;
}

elf_64_parser::elf_64_parser(std::vector<std::uint8_t> bytes) {

	std::cout<<"64"<<std::endl;
	
	// parse file header
        for (int i=0; i<10; i++) elfHeader.e_ident.push_back(bytes[i]);
	bool bigEndian = bytes[5] == 2;
        elfHeader.e_type = 	join_bytes(bytes.begin()+e_type_offset,
						e_type_size, bigEndian);
        elfHeader.e_machine = 	join_bytes(bytes.begin()+e_machine_offset,
						e_machine_size, bigEndian);
        elfHeader.e_version = 	join_bytes(bytes.begin()+e_version_offset,
						e_version_size, bigEndian);
        elfHeader.e_entry = 	join_bytes(bytes.begin()+e_entry_offset,
						e_entry_64_size, bigEndian);
        elfHeader.e_phoff = 	join_bytes(bytes.begin()+e_phoff_64_offset,
						e_phoff_64_size, bigEndian);
        elfHeader.e_shoff = 	join_bytes(bytes.begin()+e_shoff_64_offset,
						e_shoff_64_size, bigEndian);
        elfHeader.e_flags = 	join_bytes(bytes.begin()+e_flags_64_offset,
						e_flags_size, bigEndian);
        elfHeader.e_ehsize = 	join_bytes(bytes.begin()+e_ehsize_64_offset,
						e_ehsize_size, bigEndian);
        elfHeader.e_phentsize = join_bytes(bytes.begin()+e_phentsize_64_offset,
						e_phentsize_size, bigEndian);
        elfHeader.e_phnum = 	join_bytes(bytes.begin()+e_phnum_64_offset,
						e_phnum_size, bigEndian);
        elfHeader.e_shentsize = join_bytes(bytes.begin()+e_shentsize_64_offset,
						e_shentsize_size, bigEndian);
        elfHeader.e_shnum = 	join_bytes(bytes.begin()+e_shnum_64_offset,
						e_shnum_size, bigEndian);
        elfHeader.e_shstrndx = 	join_bytes(bytes.begin()+e_shstrndx_64_offset,
						e_shstrndx_size, bigEndian);

	// parse program headers
        for (int i=0; i<elfHeader.e_phnum; i++) {
                int offset = elfHeader.e_phoff + elfHeader.e_phentsize*i;
                std::cout << i << "\t" << offset << std::endl;
        }
        std::cout<<elfHeader.e_phnum<<std::endl;
}

} // end of namespace elf
