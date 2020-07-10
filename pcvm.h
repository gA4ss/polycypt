#ifndef PCVM_H
#define PCVM_H

#define SUPPORT_DEBUGER

#include <pcfile.h>
#include <cctype>

#ifdef SUPPORT_DEBUGER
#include <string>
#endif

enum PCVM_REG {
	PCVM_REG_IP,
	PCVM_REG_SB,
	PCVM_REG_SP,
	PCVM_REG_RET,
	PCVM_REG_R4,
	PCVM_REG_R5,
	PCVM_REG_R6,
	PCVM_REG_R7,
	PCVM_REG_R8,
	PCVM_REG_R9,
	PCVM_REG_R10,
	PCVM_REG_R11,
	PCVM_REG_R12,
	PCVM_REG_R13,
	PCVM_REG_R14,
	PCVM_REG_R15,
	PCVM_REG_NUMBER
};

enum PCVM_OP {
	PCVM_OP_MOV,
	PCVM_OP_PUSH,
	PCVM_OP_POP,
	PCVM_OP_CMP,
	PCVM_OP_CALL,
	PCVM_OP_RET,
	PCVM_OP_JMP,
	PCVM_OP_JE,
	PCVM_OP_JNE,
	PCVM_OP_JB,
	PCVM_OP_JA,
	PCVM_OP_JBE,
	PCVM_OP_JAE,
	PCVM_OP_AND,
	PCVM_OP_OR,
	PCVM_OP_NOT,
	PCVM_OP_ADD,
	PCVM_OP_SUB,
	PCVM_OP_MUL,
	PCVM_OP_DIV,
	PCVM_OP_MOD,
	PCVM_OP_SHL,
	PCVM_OP_SHR,
	PCVM_OP_INT,
	PCVM_OP_NOP,
	PCVM_OP_NUMBER
};

/*
 * PCVM_INS_MODE_OP:              |5:opcode|3:mode|24:-|
 * PCVM_INS_MODE_OP_IMM:          |5:opcode|3:mode|4:-|20:imm|
 * PCVM_INS_MODE_OP_REG:          |5:opcode|3:mode|4:reg|20:-|
 * PCVM_INS_MODE_OP_REG_IMM:			|5:opcode|3:mode|4:reg|20:imm|
 * PCVM_INS_MODE_OP_REG_REG:			|5:opcode|3:mode|4:reg1|4:reg2|16:-|
 * PCVM_INS_MODE_OP_MEM_IMM:			|5:opcode|3:mode|4:reg|20:imm|
 * PCVM_INS_MODE_OP_MEM_REG:			|5:opcode|3:mode|4:reg1|4:reg2|16:-|
 * PCVM_INS_MODE_OP_MEM_MEM:			|5:opcode|3:mode|4:reg1|4:reg2|16:-|
 */
enum PCVM_INS_MODE {
	PCVM_INS_MODE_OP,             /* opcode */
	PCVM_INS_MODE_OP_IMM,         /* opcode imm */
	PCVM_INS_MODE_OP_REG,         /* opcode reg */
	PCVM_INS_MODE_OP_REG_IMM,			/* opcode reg, imm */
	PCVM_INS_MODE_OP_REG_REG,			/* opcode reg, reg */
	PCVM_INS_MODE_OP_MEM_IMM,			/* opcode mem, imm */
	PCVM_INS_MODE_OP_MEM_REG,			/* opcode mem, reg */
	PCVM_INS_MODE_OP_MEM_MEM,			/* opcode mem, mem */
	PCVM_INS_MODE_NUMBER
};

typedef struct {
	unsigned int opcode : 5;
	unsigned int mode : 3;
	unsigned int reserve : 24;
} pcvm_ins_mode_op;

typedef struct {
	unsigned int opcode : 5;
	unsigned int mode : 3;
	unsigned int reserve : 4;
	unsigned int imm : 20;
} pcvm_ins_mode_op_imm;

typedef struct {
	unsigned int opcode : 5;
	unsigned int mode : 3;
	unsigned int reg : 4;
	unsigned int reserve : 20;
} pcvm_ins_mode_op_reg;

typedef struct {
	unsigned int opcode : 5;
	unsigned int mode : 3;
	unsigned int reg : 4;
	unsigned int imm : 20;
} pcvm_ins_mode_op_reg_imm;

typedef struct {
	unsigned int opcode : 5;
	unsigned int mode : 3;
	unsigned int reg1 : 4;
	unsigned int reg2 : 4;
	unsigned int reserve : 16;
} pcvm_ins_mode_op_reg_reg;

typedef struct {
	unsigned int opcode : 5;
	unsigned int mode : 3;
	unsigned int reg : 4;
	unsigned int imm : 20;
} pcvm_ins_mode_op_mem_imm;

typedef struct {
	unsigned int opcode : 5;
	unsigned int mode : 3;
	unsigned int reg1 : 4;
	unsigned int reg2 : 4;
	unsigned int reserve : 16;
} pcvm_ins_mode_op_mem_reg;

typedef struct {
	unsigned int opcode : 5;
	unsigned int mode : 3;
	unsigned int reg1 : 4;
	unsigned int reg2 : 4;
	unsigned int reserve : 16;
} pcvm_ins_mode_op_mem_mem;

typedef struct {
	unsigned int C : 1;
	unsigned int Z : 1;
	unsigned int S : 1;
	unsigned int O : 1;
	unsigned int A : 3;
	unsigned int reserve : 25;
} pcvm_flags_register;

enum {
	PCVM_ERROR_SUCCESS,
	PCVM_ERROR_ALLOC_FAILED,
	PCVM_ERROR_OVER_CODE_SIZE_LIMIT,
	PCVM_ERROR_INVALID_ADDRESS,
	PCVM_ERROR_INVALID_REGISTER,
	PCVM_ERROR_INVALID_OPCODE,
	PCVM_ERROR_INVALID_MODE,
	PCVM_ERROR_INVALID_INT_NUMBER,
	PCVM_ERROR_INVALID_INT_PARAM,
	PCVM_ERROR_INVALID_IO_ACCESS,
	PCVM_ERROR_IO_NOT_BOUNAD,
	PCVM_ERROR_INVALID_FLAG_A,
	PCVM_ERROR_UNKNOW,
	PCVM_ERROR_NUMBER
};

enum {
	PCVM_IO_INPUT_0,
	PCVM_IO_INPUT_1,
	PCVM_IO_INPUT_2,
	PCVM_IO_INPUT_3,
	PCVM_IO_INPUT_NUMBER,
};

enum {
	PCVM_IO_OUTPUT_0,
	PCVM_IO_OUTPUT_1,
	PCVM_IO_OUTPUT_2,
	PCVM_IO_OUTPUT_3,
	PCVM_IO_OUTPUT_NUMBER,
};

class pcvm;
typedef bool(pcvm::*ins_handle_fptr)(unsigned ins, unsigned mode);

const int SPACE_SIZE = 1024 * 1024;
const int STACK_SIZE = 1024 * 512;
const int CODE_SIZE = 1024 * 512;

class pcvm {
public:
	pcvm();
	virtual ~pcvm();
  
public:
  static bool is_big_endian();
  
#ifdef SUPPORT_DEBUGER
	bool disasm_all(unsigned char *buf, size_t bufsize);
#endif

	bool run(const unsigned char *codes, size_t cs, unsigned entry_offset=0
#ifdef SUPPORT_DEBUGER
		,bool debug=false
#endif
		);
	bool set_input_io(int io, unsigned char *stream);
	bool set_output_io(int io, unsigned char *stream);
  bool set_input_io_size(int io, size_t size);
  bool set_output_io_size(int io, size_t size);
  unsigned char *get_input_io(int io);
  unsigned char *get_output_io(int io);
  size_t get_input_io_size(int io);
  size_t get_output_io_size(int io);

	int error();

private:
	void reset();
	bool call(unsigned ins);
	bool invalid_register(int i);
	bool registers(int i, unsigned &v, bool four=false);
	bool set_registers(int i, unsigned r, bool four=false);
	bool read_memory(unsigned char *address, unsigned char *v);
	bool write_memory(unsigned char *address, unsigned v);

	bool readi(unsigned &i);
	bool invalid_offset(unsigned off);
	bool calc_address(unsigned off, unsigned **addr);
  unsigned short get_te16(unsigned char *address);
  unsigned int get_te32(unsigned char *address);
  void set_te16(unsigned char *address, unsigned short v);
  void set_te32(unsigned char *address, unsigned v);

	bool handle_ins_mode_op(unsigned ins, unsigned &op);
	bool handle_ins_mode_op_imm(unsigned ins, unsigned &op, unsigned &imm);
	bool handle_ins_mode_op_reg(unsigned ins, unsigned &op, unsigned &reg);
	bool handle_ins_mode_op_reg_imm(unsigned ins, unsigned &op,
		unsigned &reg, unsigned &imm);
	bool handle_ins_mode_op_reg_reg(unsigned ins, unsigned &op,
		unsigned &reg1, unsigned &reg2);
	bool handle_ins_mode_op_mem_imm(unsigned ins, unsigned &op,
		unsigned **address, unsigned &imm);
	bool handle_ins_mode_op_mem_reg(unsigned ins, unsigned &op,
		unsigned **address, unsigned &reg);
	bool handle_ins_mode_op_mem_mem(unsigned ins, unsigned &op,
		unsigned **address1, unsigned **address2);

	bool ins_2_opocde_mode(unsigned ins, unsigned &opcode, unsigned &mode);
	bool ins_2_mode_op(unsigned ins, pcvm_ins_mode_op &mode);
	bool ins_2_mode_op_imm(unsigned ins, pcvm_ins_mode_op_imm &mode);
	bool ins_2_mode_op_reg(unsigned ins, pcvm_ins_mode_op_reg &mode);
	bool ins_2_mode_op_reg_imm(unsigned ins, pcvm_ins_mode_op_reg_imm &mode);
	bool ins_2_mode_op_reg_reg(unsigned ins, pcvm_ins_mode_op_reg_reg &mode);
	bool ins_2_mode_op_mem_imm(unsigned ins, pcvm_ins_mode_op_mem_imm &mode);
	bool ins_2_mode_op_mem_reg(unsigned ins, pcvm_ins_mode_op_mem_reg &mode);
	bool ins_2_mode_op_mem_mem(unsigned ins, pcvm_ins_mode_op_mem_mem &mode);

	bool iMOV(unsigned ins, unsigned mode);
	bool iPUSH(unsigned ins, unsigned mode);
	bool iPOP(unsigned ins, unsigned mode);
	bool iCMP(unsigned ins, unsigned mode);
	bool iCALL(unsigned ins, unsigned mode);
	bool iRET(unsigned ins, unsigned mode);
	bool iJMP(unsigned ins, unsigned mode);
	bool iJE(unsigned ins, unsigned mode);
	bool iJNE(unsigned ins, unsigned mode);
	bool iJB(unsigned ins, unsigned mode);
	bool iJA(unsigned ins, unsigned mode);
	bool iJBE(unsigned ins, unsigned mode);
	bool iJAE(unsigned ins, unsigned mode);
	bool iAND(unsigned ins, unsigned mode);
	bool iOR(unsigned ins, unsigned mode);
	bool iNOT(unsigned ins, unsigned mode);
	bool iADD(unsigned ins, unsigned mode);
	bool iSUB(unsigned ins, unsigned mode);
	bool iMUL(unsigned ins, unsigned mode);
	bool iDIV(unsigned ins, unsigned mode);
	bool iMOD(unsigned ins, unsigned mode);
	bool iSHL(unsigned ins, unsigned mode);
	bool iSHR(unsigned ins, unsigned mode);
	bool iINT(unsigned ins, unsigned mode);
	bool iNOP(unsigned ins, unsigned mode);

#ifdef SUPPORT_DEBUGER
	void show_dbg_info();
	bool disasm(unsigned ins, std::string &out);
	void debugger(unsigned curr_ip);
#endif

private:
	unsigned _registers[PCVM_REG_NUMBER];
	pcvm_flags_register _flags;
	unsigned char *_space;
	unsigned char *_code;
	unsigned char *_stack;
	size_t _code_size;
	size_t _stack_size;
	ins_handle_fptr _handles[PCVM_OP_NUMBER];
	unsigned char *_io_input[PCVM_IO_INPUT_NUMBER];
	unsigned char *_io_output[PCVM_IO_OUTPUT_NUMBER];
  size_t _io_input_size[PCVM_IO_INPUT_NUMBER];
  size_t _io_output_size[PCVM_IO_OUTPUT_NUMBER];
	bool _shutdown;
  bool _is_big_endian;
  
	int _error;
};


#endif