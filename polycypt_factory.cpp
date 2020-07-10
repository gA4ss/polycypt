#include <polycypt_factory.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>

static std::string s_read_file(const std::string &path) {
  std::fstream file;
  
  file.open(path, std::ios::in);
  if (file.is_open() == false) {
    return "";
  }
  file.seekg(0, std::ios::end);
  size_t s = static_cast<size_t>(file.tellg());
  char *buf = new char[s + 1];
  memset(buf, 0, s+1);
  if (buf == nullptr) return "";
  file.seekg(0, std::ios::beg);
  file.read(buf, s);
  file.close();
  std::string out = buf;
  if (buf) delete[] buf;
  return out;
}

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

polycypt_factory::polycypt_factory()
{
	reset();
	srand((unsigned)time(nullptr));
}

polycypt_factory::~polycypt_factory()
{
}

bool polycypt_factory::generate(std::string & encrypt, std::string & decrypt)
{
  if (generate_encrypt(encrypt) == false) {
    _error = POLYCYPT_ERROR_GENALG;
    return false;
  }
  if (generate_decrypt(decrypt) == false) {
    _error = POLYCYPT_ERROR_GENALG;
    return false;
  }
  return true;
}

bool polycypt_factory::compile(const std::string &encrypt, const std::string &decrypt) {
  pcasm::init();
  if (_asmer.compile(encrypt, _encrypt_bytecodes, false) == false) {
    _error = POLYCYPT_ERROR_COMPILE;
    return false;
  }
  
  pcasm::init();
  if (_asmer.compile(decrypt, _decrypt_bytecodes, false) == false) {
    _error = POLYCYPT_ERROR_COMPILE;
    return false;
  }
  
  return true;
}

static bool s_write_text_file(const std::string &path, const std::string &text) {
  std::fstream file;
  
  file.open(path, std::ios::out);
  if (file.is_open() == false) {
    return false;
  }
  
  file << text;
  
  file.close();
  return true;
}

bool polycypt_factory::make(const std::string &output_dir, const std::string &template_dir, bool generate_source) {
  
  std::string template_file = template_dir;
  if (*template_file.end() != '/') {
    template_file.append("/");
  }
  template_file.append("startup.asm");
  _startup_template = s_read_file(template_file);
  if (_startup_template == "") {
    _error = POLYCYPT_ERROR_READ_FILE;
    return false;
  }
  
  std::string local_dir = output_dir;
  if (*local_dir.end() != '/') {
    local_dir.append("/");
  }
  
  std::string encrypt_source, decrypt_source;
  if (generate(encrypt_source, decrypt_source) == false) {
    return false;
  }
  
  /* output source */
  if (generate_source) {
    std::string encrypt_source_path, decrypt_source_path;
    encrypt_source_path = local_dir + "encrypt.asm";
    decrypt_source_path = local_dir + "decrypt.asm";
    if (s_write_text_file(encrypt_source_path, encrypt_source) == false) {
      _error = POLYCYPT_ERROR_WRITE_FILE;
      return false;
    }
    if (s_write_text_file(decrypt_source_path, decrypt_source) == false) {
      _error = POLYCYPT_ERROR_WRITE_FILE;
      return false;
    }
  }
  
  if (compile(encrypt_source, decrypt_source) == false) {
    return false;
  }
  
  if (pcasm::pclink(_encrypt_bytecodes) != PCASM_ERROR_SUCCESS) {
    _error = POLYCYPT_ERROR_LINK;
    return false;
  }
  
  if (pcasm::pclink(_decrypt_bytecodes) != PCASM_ERROR_SUCCESS) {
    _error = POLYCYPT_ERROR_LINK;
    return false;
  }
  
  /* make pc file */
  std::string en_file, de_file;
  en_file = local_dir + "encrypt.pbc";
  de_file = local_dir + "decrypt.pbc";
  
  if (make_pcfile(en_file, _encrypt_bytecodes) == false) {
    return false;
  }
  
  if (make_pcfile(de_file, _decrypt_bytecodes) == false) {
    return false;
  }
  
  return true;
}

void polycypt_factory::reset()
{
	_ip = 0;
	memset(&_registers, 0, sizeof(unsigned) * PCVM_REG_NUMBER);
	memset(&_idle_registers, false, sizeof(bool) * PCVM_REG_NUMBER);
	_error = PCVM_ERROR_SUCCESS;
}

bool polycypt_factory::make_symbol(std::string & symbol)
{
	return false;
}

int polycypt_factory::random(size_t n)
{
	return rand() % n;
}

bool polycypt_factory::make_pcfile(const std::string &path, std::vector<unsigned char> &bytecodes)
{
  unsigned char *buf = nullptr;
  size_t buf_size = 0;
  unsigned error = 0;
  if ((error = pcasm::pclink(bytecodes)) != PCASM_ERROR_SUCCESS) {
    _error = POLYCYPT_ERROR_LINK;
    return false;
  }
  
  buf_size = bytecodes.size();
  buf = new unsigned char[buf_size];
  unsigned char *ptr = buf;
  for (auto c : bytecodes) *ptr++ = c;
  
  unsigned char *pcfile = nullptr;
  size_t pcfile_size = 0;
  if (_asmer.make_pcfile(buf, buf_size, &pcfile, pcfile_size) == false) {
    _error = POLYCYPT_ERROR_MAKEPCF;
    return false;
  }
  
  if (buf) delete[] buf;
  
  if (s_write_obj_file(path, pcfile, pcfile_size) == false) {
    _error = POLYCYPT_ERROR_WRITE_FILE;
    return false;
  }
  if (pcfile) delete[] pcfile;
  
  return true;
}

bool polycypt_factory::generate_encrypt(std::string &encrypt) {
  return false;
}

bool polycypt_factory::generate_decrypt(std::string &decrypt) {
  return false;
}
