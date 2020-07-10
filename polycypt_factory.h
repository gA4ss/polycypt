#ifndef POLYCYPT_FACTORY_H
#define POLYCYPT_FACTORY_H

#include <pcasm.h>
#include <polycypt_error.h>

#include <vector>
#include <string>

class polycypt_factory {
public:
	polycypt_factory();
	virtual ~polycypt_factory();

	virtual bool generate(std::string &encrypt, std::string &decrypt);
	virtual bool compile(const std::string &encrypt, const std::string &decrypt);
  virtual bool make(const std::string &output_dir, const std::string &template_dir, bool generate_source=false);

protected:
	virtual void reset();
	virtual bool make_symbol(std::string &symbol);
	virtual int random(size_t n = 100);
  virtual bool make_pcfile(const std::string &path, std::vector<unsigned char> &bytecodes);

protected:
  virtual bool generate_encrypt(std::string &encrypt);
  virtual bool generate_decrypt(std::string &decrypt);
  
protected:
	unsigned _ip;
	unsigned _registers[PCVM_REG_NUMBER];
	bool _idle_registers[PCVM_REG_NUMBER];
	int _error;
  
  std::string _startup_template;
  pcasm _asmer;
  std::vector<unsigned char> _encrypt_bytecodes;
  std::vector<unsigned char> _decrypt_bytecodes;
};


#endif