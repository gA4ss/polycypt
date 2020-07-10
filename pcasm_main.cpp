#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <pcasm.h>

static bool s_write_obj_file(const std::string &path, 
	unsigned char *context, size_t len) {
	std::fstream file;

	file.open(path, std::ios::out | std::ios::binary);
	if (file.is_open() == false) {
		return false;
	}

	for (size_t i= 0; i < len; i++) {
		file.put(context[i]);
	}
	
	file.close();
	return true;
}

void usage() {
	printf("usage: pcasm <asm file> [out file]\r\n");
	return;
}

int main(int argc, char *argv[]) {
	pcasm asmer;
	std::string source;
	std::string bytefile = "./out.pbc";
	std::vector<unsigned char> bytecodes;
	int error = 0;
  
	if ((argc < 2) || (argc >= 4)) {
		usage();
		return 0;
	}

	if (argc == 3) {
		bytefile = argv[2];
	}
	source = argv[1];

	printf("compiling %s...\r\n", source.c_str());

	pcasm::init();
	if (asmer.make(source, bytecodes)) {
		unsigned char *buf = nullptr;
		size_t buf_size = 0;

		if ((error = pcasm::pclink(bytecodes)) != PCASM_ERROR_SUCCESS) {
			printf("[-] link error : %d\r\n", error);
			return error;
		}

		buf_size = bytecodes.size();
		buf = new unsigned char[buf_size];
		unsigned char *ptr = buf;
		for (auto c : bytecodes) {
			*ptr++ = c;
		}

		unsigned char *pcfile = nullptr;
		size_t pcfile_size = 0;
		if (asmer.make_pcfile(buf, buf_size, &pcfile, pcfile_size) == false) {
			printf("[-] make polycypt format file error\r\n");
			return -1;
		}

		if (buf) delete[] buf;

		if (s_write_obj_file(bytefile, pcfile, pcfile_size) == false) {
			printf("[-] write bytecode file : %s error\r\n", bytefile.c_str());
			return -1;
		}
		if (pcfile) delete[] pcfile;
	}
	else {
		error = asmer.error();
		printf("[-] compile error : %d\r\n", error);
		return error;
	}

	printf("success\r\n");
	return 0;
}