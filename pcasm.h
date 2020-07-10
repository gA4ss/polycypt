#ifndef PCASM_H
#define PCASM_H

#include <string>
#include <vector>
#include <map>

#ifdef _MSC_VER
#include <memory>
#endif

#include <pcfile.h>
#include <pcvm.h>

enum {
	TOKEN_OP,
	TOKEN_REG,
	TOKEN_IMM,
	TOKEN_DEF_LABEL,
  TOKEN_REF_LABEL,
	TOKEN_COLON,
	TOKEN_LPARAM,
	TOKEN_RPARAM,
	TOKEN_COMMA,
	TOKEN_INCLUDE,
	TOKEN_STRING,
	TOKEN_EOF,
	TOKEN_NUMBER
};

enum {
	PCASM_ERROR_SUCCESS,
	PCASM_ERROR_ALLOC_MEMORY,
	PCASM_ERROR_CODE_OVER_LIMIT,
	PCASM_ERROR_SCAN_TOKEN,
	PCASM_ERROR_SCAN_QUOTATION_NOT_CLOSE,
	PCASM_ERROR_SCAN_INVALID_CHAR,
  PCASM_ERROR_SCAN_NOT_MATCH_TOKEN,
	PCASM_ERROR_SCAN_LABNAME_OVER_LIMIT,
  PCASM_ERROR_SCAN_NOT_MATCH_TOKEN_START_CHAR,
	PCASM_ERROR_SYNTAX_SAME_LABEL,
	PCASM_ERROR_SYNTAX_INCONFORMITY_TOKEN,
	PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN,
	PCASM_ERROR_LINK_NOT_FOUND_LABEL,
  PCASM_ERROR_MAKE_NOT_FOUND_STARTUP_LABEL,
	PCASM_ERROR_NUMBER
};

#define PCASM_MAX_LABEL			64

typedef struct {
	unsigned opcode;
	std::string str;
	unsigned reg;
	unsigned imm;
	std::vector<unsigned char> data;
} pcasm_text;

typedef struct {
	unsigned address;
	unsigned mode_address;
} pcasm_label;

enum {
	PCASM_REL_FIXLST20B,
	PCASM_REL_NUMBER
};

typedef struct {
	int type;
	unsigned address;
	std::string symbol;
} pcasm_relocate;

typedef struct {
	int token;
	pcasm_text text;
} pcasm_token;

class pcasm;
typedef bool(pcasm::*ins_compile_fptr)(std::vector<unsigned char> &bytecodes);

class pcasm {
public:
	pcasm();
	virtual ~pcasm();

	bool compile(const std::string &asm_file, std::vector<unsigned char> &bytecodes, bool is_file=true);
	bool make(const std::string &asm_file, std::vector<unsigned char> &bytecodes);
	bool make_pcfile(unsigned char *bytecodes, size_t bcsize, unsigned char **pcfile, size_t &pcfile_size);
	int error();

public:
	static void init();
	static int pclink(std::vector<unsigned char> &bytecodes);
	static unsigned entry();

private:
	void reset();

	unsigned write_mode_op(unsigned opcode);
	unsigned write_mode_op_imm(unsigned opcode, unsigned imm);
	unsigned write_mode_op_reg(unsigned opcode, unsigned reg);
	unsigned write_mode_op_reg_imm(unsigned opcode, unsigned reg, unsigned imm);
	unsigned write_mode_op_reg_reg(unsigned opcode, unsigned reg1, unsigned reg2);
	unsigned write_mode_op_mem_imm(unsigned opcode, unsigned reg, unsigned imm);
	unsigned write_mode_op_mem_reg(unsigned opcode, unsigned reg1, unsigned reg2);
	unsigned write_mode_op_mem_mem(unsigned opcode, unsigned reg1, unsigned reg2);
	
	bool MOV_REG_LAB(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool MOV_MEM_LAB(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool MOV_REG_IMM(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool MOV_REG_REG(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool MOV_MEM_IMM(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool MOV_MEM_REG(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool MOV_MEM_MEM(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool cMOV(std::vector<unsigned char> &bytecodes);

	bool PUSH_LAB(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool PUSH_IMM(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool PUSH_REG(unsigned opcode, std::vector<unsigned char> &bytecodes);
	bool cPUSH(std::vector<unsigned char> &bytecodes);

	bool POP_REG(std::vector<unsigned char> &bytecodes);
	bool cPOP(std::vector<unsigned char> &bytecodes);

	bool CMP_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool CMP_REG_REG(std::vector<unsigned char> &bytecodes);
	bool CMP_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool CMP_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool CMP_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cCMP(std::vector<unsigned char> &bytecodes);

	bool CALL_LAB(std::vector<unsigned char> &bytecodes);
	bool CALL_IMM(std::vector<unsigned char> &bytecodes);
	bool CALL_REG(std::vector<unsigned char> &bytecodes);
	bool cCALL(std::vector<unsigned char> &bytecodes);

	bool cRET(std::vector<unsigned char> &bytecodes);

	bool JMP_LAB(std::vector<unsigned char> &bytecodes);
	bool JMP_IMM(std::vector<unsigned char> &bytecodes);
	bool JMP_REG(std::vector<unsigned char> &bytecodes);
	bool cJMP(std::vector<unsigned char> &bytecodes);

	bool JE_LAB(std::vector<unsigned char> &bytecodes);
	bool JE_IMM(std::vector<unsigned char> &bytecodes);
	bool JE_REG(std::vector<unsigned char> &bytecodes);
	bool cJE(std::vector<unsigned char> &bytecodes);

	bool JNE_LAB(std::vector<unsigned char> &bytecodes);
	bool JNE_IMM(std::vector<unsigned char> &bytecodes);
	bool JNE_REG(std::vector<unsigned char> &bytecodes);
	bool cJNE(std::vector<unsigned char> &bytecodes);

	bool JB_LAB(std::vector<unsigned char> &bytecodes);
	bool JB_IMM(std::vector<unsigned char> &bytecodes);
	bool JB_REG(std::vector<unsigned char> &bytecodes);
	bool cJB(std::vector<unsigned char> &bytecodes);

	bool JA_LAB(std::vector<unsigned char> &bytecodes);
	bool JA_IMM(std::vector<unsigned char> &bytecodes);
	bool JA_REG(std::vector<unsigned char> &bytecodes);
	bool cJA(std::vector<unsigned char> &bytecodes);

	bool JBE_LAB(std::vector<unsigned char> &bytecodes);
	bool JBE_IMM(std::vector<unsigned char> &bytecodes);
	bool JBE_REG(std::vector<unsigned char> &bytecodes);
	bool cJBE(std::vector<unsigned char> &bytecodes);

	bool JAE_LAB(std::vector<unsigned char> &bytecodes);
	bool JAE_IMM(std::vector<unsigned char> &bytecodes);
	bool JAE_REG(std::vector<unsigned char> &bytecodes);
	bool cJAE(std::vector<unsigned char> &bytecodes);

  bool AND_REG_LAB(std::vector<unsigned char> &bytecodes);
  bool AND_MEM_LAB(std::vector<unsigned char> &bytecodes);
	bool AND_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool AND_REG_REG(std::vector<unsigned char> &bytecodes);
	bool AND_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool AND_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool AND_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cAND(std::vector<unsigned char> &bytecodes);

  bool OR_REG_LAB(std::vector<unsigned char> &bytecodes);
  bool OR_MEM_LAB(std::vector<unsigned char> &bytecodes);
	bool OR_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool OR_REG_REG(std::vector<unsigned char> &bytecodes);
	bool OR_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool OR_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool OR_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cOR(std::vector<unsigned char> &bytecodes);

	bool NOT_REG(std::vector<unsigned char> &bytecodes);
	bool cNOT(std::vector<unsigned char> &bytecodes);

  bool ADD_REG_LAB(std::vector<unsigned char> &bytecodes);
  bool ADD_MEM_LAB(std::vector<unsigned char> &bytecodes);
	bool ADD_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool ADD_REG_REG(std::vector<unsigned char> &bytecodes);
	bool ADD_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool ADD_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool ADD_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cADD(std::vector<unsigned char> &bytecodes);

  bool SUB_REG_LAB(std::vector<unsigned char> &bytecodes);
  bool SUB_MEM_LAB(std::vector<unsigned char> &bytecodes);
	bool SUB_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool SUB_REG_REG(std::vector<unsigned char> &bytecodes);
	bool SUB_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool SUB_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool SUB_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cSUB(std::vector<unsigned char> &bytecodes);

  bool MUL_REG_LAB(std::vector<unsigned char> &bytecodes);
  bool MUL_MEM_LAB(std::vector<unsigned char> &bytecodes);
	bool MUL_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool MUL_REG_REG(std::vector<unsigned char> &bytecodes);
	bool MUL_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool MUL_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool MUL_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cMUL(std::vector<unsigned char> &bytecodes);

  bool DIV_REG_LAB(std::vector<unsigned char> &bytecodes);
  bool DIV_MEM_LAB(std::vector<unsigned char> &bytecodes);
	bool DIV_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool DIV_REG_REG(std::vector<unsigned char> &bytecodes);
	bool DIV_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool DIV_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool DIV_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cDIV(std::vector<unsigned char> &bytecodes);

  bool MOD_REG_LAB(std::vector<unsigned char> &bytecodes);
  bool MOD_MEM_LAB(std::vector<unsigned char> &bytecodes);
	bool MOD_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool MOD_REG_REG(std::vector<unsigned char> &bytecodes);
	bool MOD_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool MOD_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool MOD_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cMOD(std::vector<unsigned char> &bytecodes);

  bool SHL_REG_LAB(std::vector<unsigned char> &bytecodes);
  bool SHL_MEM_LAB(std::vector<unsigned char> &bytecodes);
	bool SHL_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool SHL_REG_REG(std::vector<unsigned char> &bytecodes);
	bool SHL_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool SHL_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool SHL_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cSHL(std::vector<unsigned char> &bytecodes);

  bool SHR_REG_LAB(std::vector<unsigned char> &bytecodes);
  bool SHR_MEM_LAB(std::vector<unsigned char> &bytecodes);
	bool SHR_REG_IMM(std::vector<unsigned char> &bytecodes);
	bool SHR_REG_REG(std::vector<unsigned char> &bytecodes);
	bool SHR_MEM_IMM(std::vector<unsigned char> &bytecodes);
	bool SHR_MEM_REG(std::vector<unsigned char> &bytecodes);
	bool SHR_MEM_MEM(std::vector<unsigned char> &bytecodes);
	bool cSHR(std::vector<unsigned char> &bytecodes);

	bool INT_IMM(std::vector<unsigned char> &bytecodes);
	bool cINT(std::vector<unsigned char> &bytecodes);

	bool cNOP(std::vector<unsigned char> &bytecodes);

	bool cInclude(std::vector<unsigned char> &bytecodes);
	bool cDefLabel(pcasm_token &token);

	bool pass1();
	bool pass2(std::vector<unsigned char> &bytecodes);

	bool scanner(pcasm_token &token);
	bool parser(std::vector<unsigned char> &bytecodes);
	void set_error(int err);
	bool match(std::vector<int> tokens);

	bool plus_address(unsigned plus=sizeof(unsigned));

private:
	bool teste();
	int readc();
	bool plusp(int plus=1);
	bool decp(int dec=1);

	int write_ins(int ins, std::vector<unsigned char> &bytecodes);
	int write_datas(const std::vector<unsigned char> &datas, std::vector<unsigned char> &bytecodes);
	int write_imm(unsigned data, std::vector<unsigned char> &bytecodes);
	int write_string(const std::string &str, std::vector<unsigned char> &bytecodes);

	pcasm_token next_token();
	void rollback_token(int num = 1);

private:
	ins_compile_fptr _handles[PCVM_OP_NUMBER];
	std::string _source;
	std::vector<pcasm_text> _text_stack;
	std::vector<pcasm_token> _token_source;

	size_t _pos;
	size_t _token_pos;
	unsigned _address;
	int _error;
	int _err_on_token;
	std::string _errstr;
};

#endif