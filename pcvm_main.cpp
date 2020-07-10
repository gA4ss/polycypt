#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>

#include <fstream>
#include <vector>
#include <pcfile.h>
#include <pcvm.h>

bool s_read_bin_file(const std::string &path, unsigned char**buf, size_t &bufsize) {
	std::fstream file;

	assert(buf);

	file.open(path, std::ios::in | std::ios::binary);
	if (file.is_open() == false) {
		return false;
	}
	file.seekg(0, std::ios::end);
	size_t s = static_cast<size_t>(file.tellg());
	bufsize = s;
	*buf = new unsigned char[bufsize + 1];
	memset(*buf, 0, bufsize + 1);
	if (*buf == nullptr) return false;
	file.seekg(0, std::ios::beg);
	file.read(reinterpret_cast<char*>(*buf), bufsize);
	file.close();
	return true;
}

static bool s_write_obj_file(const std::string &path, unsigned char *context, size_t len) {
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
	printf("usage: pcvm [options] <bytecode file>\r\n");
  printf("-d                disasm\r\n");
  printf("-i <port> <file>  bind input io to file\r\n");
  printf("-o <port> <file>  bind output io to file\r\n");
	return;
}

typedef struct {
  bool disasm;
  bool bind_input_io;
  bool bind_output_io;
  
  int input_io;
  int output_io;
  std::string input_io_file;
  std::string output_io_file;
  
  std::string target;
} arguments_t;

bool handle_arguments(int argc, char*argv[], arguments_t &args) {
  args.disasm = false;
  args.bind_input_io = false;
  args.bind_output_io = false;
  args.input_io = 0;
  args.output_io = 0;
  args.input_io_file = "";
  args.output_io_file = "";
  args.target = "";
  
  int i = 1;
  while (true) {
    
    if (i == argc-1) {
      args.target = argv[i];
      break;
    }
    
    if (strcmp(argv[i], "-d") == 0) {
      args.disasm = true;
    }
    else if (strcmp(argv[i], "-i") == 0) {
      args.bind_input_io = true;
      i++;
      if (i >= argc-2) return false;
      args.input_io = static_cast<int>(atoi(argv[i]));
      i++;
      if (i >= argc-1) return false;
      args.input_io_file = argv[i];
    }
    else if (strcmp(argv[i], "-o") == 0) {
      args.bind_output_io = true;
      i++;
      if (i >= argc-2) return false;
      args.output_io = static_cast<int>(atoi(argv[i]));
      i++;
      if (i >= argc-1) return false;
      args.output_io_file = argv[i];
    }
    i++;
  }
  
  return true;
}

static unsigned char s_input_io_0[256] = { 0 };
static unsigned char s_output_io_0[1024*1024] = { 0 };
static unsigned char *s_input_io_bind = nullptr;
static size_t s_input_io_size = 0;
static size_t s_output_io_size = 0;
int main(int argc, char *argv[]) {
  	if (argc == 1) {
		usage();
		return -1;
	}

	unsigned char *codes = nullptr;
	size_t codesize = 0;
	pcvm vm;
  strcpy((char*)s_input_io_0, "hello world");
  vm.set_input_io(0, s_input_io_0);
  vm.set_input_io_size(0, strlen((char*)s_input_io_0));
  vm.set_output_io(0, s_output_io_0);

  arguments_t args;
  if (handle_arguments(argc, argv, args) == false) {
    usage();
    return -1;
  }
  
	if (args.disasm) {
		if (s_read_bin_file(args.target, &codes, codesize) == false) {
			printf("read %s error\r\n", argv[2]);
		}

		pcfile_header *hdr = reinterpret_cast<pcfile_header*>(codes);
		if (hdr->magic != PCMAGIC) {
			printf("invalid polycypt format file\r\n");
			return -1;
		}
		unsigned entry = hdr->entry;
		if (entry >= SPACE_SIZE) {
			printf("invalid entry address\r\n");
			return -1;
		}

		codesize -= sizeof(pcfile_header);
		codes += sizeof(pcfile_header);

		vm.disasm_all(codes, codesize);
    
    return 0;
	}
  
  if (args.bind_input_io) {
    int port = args.input_io;
    if (port >= PCVM_IO_INPUT_NUMBER) {
      printf("invalid io input port\r\n");
      return -1;
    }
    std::string iofile = args.input_io_file;
    if (s_read_bin_file(iofile, &s_input_io_bind, s_input_io_size) == false) {
      printf("read file error\r\n");
      return -1;
    }
    vm.set_input_io(port, s_input_io_bind);
    vm.set_input_io_size(port, s_input_io_size);
  }
  
  if (args.bind_output_io) {
    unsigned port = args.bind_output_io;
    if (port >= PCVM_IO_INPUT_NUMBER) {
      printf("invalid io output port\r\n");
      return -1;
    }
    vm.set_output_io(port, s_output_io_0);
  }

  /*
   * run pcvm
   */
  
  if (s_read_bin_file(args.target, &codes, codesize) == false) {
    printf("read %s error\r\n", argv[1]);
  }

  pcfile_header *hdr = reinterpret_cast<pcfile_header*>(codes);
  if (hdr->magic != PCMAGIC) {
    printf("invalid polycypt format file\r\n");
    return -1;
  }
  unsigned entry = hdr->entry;
  if (entry >= SPACE_SIZE) {
    printf("invalid entry address\r\n");
    return -1;
  }

  codesize -= sizeof(pcfile_header);
  codes += sizeof(pcfile_header);

  if (vm.run((unsigned char*)codes, codesize, entry, true) == false) {
    printf("error : %d\n", vm.error());
  }

  /* output to file */
  if (args.bind_output_io) {
    s_output_io_size = vm.get_output_io_size(args.output_io);
    if (s_output_io_size) {
      if (s_write_obj_file(args.output_io_file, s_output_io_0, s_output_io_size) == false) {
        printf("write file error\r\n");
        return -1;
      }
    }
  }
  
  if (s_input_io_bind) delete [] s_input_io_bind;
	return 0;
}