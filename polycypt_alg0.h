#ifndef POLYCYPT_ALG0_H
#define POLYCYPT_ALG0_H

#include <polycypt_factory.h>
#include <ostream>
#include <sstream>

enum {
	OP_AND,
	OP_OR,
	OP_NOT,
	OP_ADD,
	OP_SUB,
	OP_MUL,
	OP_DIV,
	OP_MOD,
	OP_SHL,
	OP_SHR,
  OP_ROL,
  OP_ROR,
	OP_XOR,
	OP_NUMBER
};

typedef struct {
  int binop;
  
} polycypt_alg0_formula_node;

class polycypt_alg0 : public polycypt_factory {
public:
	polycypt_alg0();
	virtual ~polycypt_alg0();

protected:
  virtual bool generate_encrypt(std::string &encrypt);
  virtual bool generate_decrypt(std::string &decrypt);
  
protected:
  virtual bool generate_xor(std::ostringstream &oss);
  virtual bool generate_keytab(std::ostringstream &oss);
  virtual bool generate_algorithm_start(std::ostringstream &oss);
  virtual bool generate_algorithm_end(std::ostringstream &oss);
  
private:
  std::ostringstream _keytab;
  int _keyidx;
};


#endif
