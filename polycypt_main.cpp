#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <pcvm.h>
#include <polycypt.h>

#ifdef _MSC_VER
#include <memory>
#endif

void usage() {
	printf("usage: polycypt [options] <output path>\r\n");
  printf("-t <template dir path>\r\n");
	return;
}

int main(int argc, char *argv[]) {

	if (argc < 2) {
  _show_help:
		usage();
		return -1;
	}
  
  std::string template_path = "./template", output_path;
  if (argc >= 3) {
    if (strcmp(argv[1], "-t") == 0) {
      template_path = argv[2];
      if (argc == 3) {
        goto _show_help;
      }
    }
  }
  output_path = argv[argc-1];
  
  polycypt_config config;
  config.factory = 0;
  polycypt pc(config);
  if (pc.run(output_path, template_path) == false) {
    printf("[-] <%d>polycypt run failed.\r\n", pc.error());
  }
  else {
    printf("generate cryptographic algorithms success\r\n");
  }
  
	return 0;
}