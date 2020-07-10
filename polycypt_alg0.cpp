#include <polycypt_alg0.h>

polycypt_alg0::polycypt_alg0() : polycypt_factory()
{
  generate_keytab(_keytab);
  _keyidx = random(256);
}

polycypt_alg0::~polycypt_alg0()
{
}

bool polycypt_alg0::generate_encrypt(std::string &encrypt) {
  std::ostringstream oss;
  generate_algorithm_start(oss);
  generate_algorithm_end(oss);
  encrypt = oss.str();
  encrypt.append(_startup_template);
  return true;
}

bool polycypt_alg0::generate_decrypt(std::string &decrypt) {
  std::ostringstream oss;
  generate_algorithm_start(oss);
  generate_algorithm_end(oss);
  decrypt = oss.str();
  decrypt.append(_startup_template);
  return true;
}

/* (~a & b) | (a & ~b) */
bool polycypt_alg0::generate_xor(std::ostringstream &oss) {
  /*
   * r10 = key
   * r11 = data
   * r12 = tmp1
   * r13 = tmp2
   */
  oss << "@xor:\n";
  oss << "push r4\n";
  oss << "sub sp, 4\n";
  oss << "mov [sp], [r11]\n";
  oss << "pop r4\n";
  oss << "not r4\n";              /* ~a */
  oss << "mov [r12], r4\n";
  oss << "and [r12], [r10]\n";    /* ~a & b */
  oss << "sub sp, 4\n";
  oss << "mov [sp], [r10]\n";
  oss << "pop r4\n";
  oss << "not r4\n";              /* ~b */
  oss << "mov [r13], [r11]\n";
  oss << "and [r13], r4\n";       /* a & ~b */
  oss << "or [r13], [r12]\n";     /* (~a & b) | (a & ~b) */
  oss << "sub sp, 4\n";
  oss << "mov [sp], [r13]\n";
  oss << "pop r3\n";
  oss << "pop r4\n";
  oss << "ret\n";
  return true;
}

bool polycypt_alg0::generate_keytab(std::ostringstream &oss) {
  oss << "@keytab:\n";
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < 16; j++) {
      char buf[64] = {0};
      sprintf(buf, "x%x", random(0xFFFFFFFF));
      oss << buf;
      oss << " ";
    }
    oss << "\n";
  }
  oss << "\n";
  return true;
}

bool polycypt_alg0::generate_algorithm_start(std::ostringstream &oss) {
  /*
   * r10 = key
   * r11 = data
   * r12 = tmp1
   * r13 = tmp2
   */
  generate_xor(oss);
  oss << _keytab.str();
  oss << "@key: 0\n";
  oss << "@data: 0\n";
  oss << "@tmp1: 0\n";
  oss << "@tmp2: 0\n";
  oss << "@algorithm:\n";
  oss << "push r5\n";
  oss << "push r4\n";
  oss << "mov r4, sp\n";
  oss << "add r4, 12\n";
  oss << "div r5, 4\n";
  
  /* get key */
  oss << "push r6\n";
  char buf[64] = {0};
  sprintf(buf, "%d", _keyidx);
  oss << "mov r6, " << buf << "\n";
  oss << "mul r6, 4\n";
  oss << "add r6, @keytab\n";
  oss << "mov r10, @key\n";
  oss << "mov [r10], [r6]\n";
  oss << "pop r6\n";
  
  /* set tmp */
  oss << "mov r12, @tmp1\n";
  oss << "mov r13, @tmp2\n";
  /* set data */
  oss << "mov r11, @data\n";
  
  /* handle */
  oss << "@loop:\n";
  oss << "cmp r5, 0\n";
  oss << "je @algorithm_end\n";
  oss << "mov [r11], [r4]\n";
  oss << "call @xor\n";
  /* save result */
  oss << "mov [r4], r3\n";
  oss << "add r4, 4\n";
  oss << "sub r5, 1\n";
  oss << "jmp @loop\n";
  return true;
}

bool polycypt_alg0::generate_algorithm_end(std::ostringstream &oss) {
  oss << "@algorithm_end:\n";
  oss << "pop r4\n";
  oss << "pop r5\n";
  oss << "ret\n";
  return true;
}




