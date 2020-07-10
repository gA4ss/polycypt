#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cassert>
#include <fstream>
#include <pcasm.h>

static std::vector<pcasm_relocate> s_relocates;
static std::map<std::string, std::shared_ptr<pcasm_label> > s_symbols;
static std::map<std::string, std::shared_ptr<pcasm> > s_sources;
static unsigned s_address;

static size_t s_up4(size_t v) {
	return ~3u & (3 + v);
}

static bool s_is_hexchar(int c) {
	if ((c >= 'a') && (c <= 'f')) {
		return true;
	}
	else if ((c >= 'A') && (c <= 'F')) {
		return true;
	}
	else if ((c >= '0') && (c <= '9')) {
		return true;
	}
	return false;
}

//static size_t s_get_file_size(const std::string &path) {
//	std::fstream file;
//
//	file.open(path, std::ios::in);
//	if (file.is_open() == false) {
//		return -1;
//	}
//	file.seekg(0, std::ios::end);
//	size_t r = static_cast<size_t>(file.tellg());
//	file.close();
//	return r;
//}

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

pcasm::pcasm()
{
	reset();
	_handles[PCVM_OP_MOV] = &pcasm::cMOV;
	_handles[PCVM_OP_PUSH] = &pcasm::cPUSH;
	_handles[PCVM_OP_POP] = &pcasm::cPOP;
	_handles[PCVM_OP_CMP] = &pcasm::cCMP;
	_handles[PCVM_OP_CALL] = &pcasm::cCALL;
	_handles[PCVM_OP_RET] = &pcasm::cRET;
	_handles[PCVM_OP_JMP] = &pcasm::cJMP;
	_handles[PCVM_OP_JE] = &pcasm::cJE;
	_handles[PCVM_OP_JNE] = &pcasm::cJNE;
	_handles[PCVM_OP_JB] = &pcasm::cJB;
	_handles[PCVM_OP_JA] = &pcasm::cJA;
	_handles[PCVM_OP_JBE] = &pcasm::cJBE;
	_handles[PCVM_OP_JAE] = &pcasm::cJAE;
	_handles[PCVM_OP_AND] = &pcasm::cAND;
	_handles[PCVM_OP_OR] = &pcasm::cOR;
	_handles[PCVM_OP_NOT] = &pcasm::cNOT;
	_handles[PCVM_OP_ADD] = &pcasm::cADD;
	_handles[PCVM_OP_SUB] = &pcasm::cSUB;
	_handles[PCVM_OP_MUL] = &pcasm::cMUL;
	_handles[PCVM_OP_DIV] = &pcasm::cDIV;
	_handles[PCVM_OP_MOD] = &pcasm::cMOD;
	_handles[PCVM_OP_SHL] = &pcasm::cSHL;
	_handles[PCVM_OP_SHR] = &pcasm::cSHR;
	_handles[PCVM_OP_INT] = &pcasm::cINT;
	_handles[PCVM_OP_NOP] = &pcasm::cNOP;
}

pcasm::~pcasm()
{
}

bool pcasm::compile(const std::string & asm_file, std::vector<unsigned char> &bytecodes, bool is_file)
{
  reset();
  
	if (is_file) {
		std::string source = s_read_file(asm_file);
		if (source == "") return false;
		_source = source;
	}
	else {
		/* use string */
		_source = asm_file;
	}
	
	if (pass1() == false) return false;
	if (pass2(bytecodes) == false) return false;

	return true;
}

bool pcasm::make(const std::string & asm_file, std::vector<unsigned char> &bytecodes)
{
	return compile(asm_file, bytecodes);
}

bool pcasm::make_pcfile(unsigned char *bytecodes, size_t bcsize, unsigned char **pcfile, size_t &pcfile_size) 
{
	assert(pcfile);

	pcfile_header header;
	header.magic = PCMAGIC;
	header.entry = entry();
  if (header.entry == 0xFFFFFFFF) {
    _error = PCASM_ERROR_MAKE_NOT_FOUND_STARTUP_LABEL;
    return false;
  }

	pcfile_size = sizeof(pcfile_header) + bcsize;
	*pcfile = new unsigned char[pcfile_size];
  if (*pcfile == nullptr) {
    _error = PCASM_ERROR_ALLOC_MEMORY;
    return false;
  }

	memcpy(*pcfile, &header, sizeof(pcfile_header));
	memcpy(*pcfile + sizeof(pcfile_header), bytecodes, bcsize);

	return true;
}

int pcasm::error()
{
	return _error;
}

void pcasm::init()
{
	s_relocates.clear();
	s_symbols.clear();
	s_sources.clear();
	s_address = 0;
}

int pcasm::pclink(std::vector<unsigned char>& bytecodes)
{
	if (bytecodes.empty()) return false;
	size_t size = bytecodes.size();
	unsigned char *ptr = new unsigned char[size + 1];
	if (ptr == nullptr) {
		return PCASM_ERROR_ALLOC_MEMORY;
	}
	
	size_t i = 0;
	for (auto b : bytecodes) {
		ptr[i++] = b;
	}

	for (auto r : s_relocates) {
		if (s_symbols.find(r.symbol) == s_symbols.end()) {
			return PCASM_ERROR_LINK_NOT_FOUND_LABEL;
		}
		unsigned ins = *reinterpret_cast<unsigned*>(ptr + r.address);
		ins |= (s_symbols[r.symbol]->address & 0xFFFFF);
		*reinterpret_cast<unsigned*>(ptr + r.address) = ins;
	}

	bytecodes.clear();
	for (size_t i = 0; i < size; i++) {
		bytecodes.push_back(ptr[i]);
	}

	if (ptr) delete[] ptr;
	return PCASM_ERROR_SUCCESS;
}

unsigned pcasm::entry()
{
	if (s_symbols.find("_start") == s_symbols.end()) {
		return 0xFFFFFFFF;
	}

	unsigned entry = s_symbols["_start"]->address;
	if (entry >= SPACE_SIZE) return 0xFFFFFFFF;

	return entry;
}

void pcasm::reset()
{
	_token_pos = 0;
	_pos = 0;
	_address = 0;
	_error = PCASM_ERROR_SUCCESS;
	_errstr.clear();
	_err_on_token = TOKEN_NUMBER;
}

/* | 5 : opcode | 3 : mode | 24 : -| */
unsigned pcasm::write_mode_op(unsigned opcode) {
	unsigned ins = 0;;
	ins = opcode << 27;
	ins |= (PCVM_INS_MODE_OP << 24);

	return ins;
}

/* | 5 : opcode | 3 : mode | 4 : -| 20 : imm | */
unsigned pcasm::write_mode_op_imm(unsigned opcode, unsigned imm) {
	unsigned ins = 0;
	ins = opcode << 27;
	ins |= (PCVM_INS_MODE_OP_IMM << 24);
	ins |= imm;

	return ins;
}

/* | 5 : opcode | 3 : mode | 4 : reg | 20 : -| */
unsigned pcasm::write_mode_op_reg(unsigned opcode, unsigned reg) {
	unsigned ins = 0;
	ins = opcode << 27;
	ins |= (PCVM_INS_MODE_OP_REG << 24);
	ins |= (reg << 20);

	return ins;
}

/* | 5 : opcode | 3 : mode | 4 : reg | 20 : imm | */
unsigned pcasm::write_mode_op_reg_imm(unsigned opcode, unsigned reg, unsigned imm) {
	unsigned ins = 0;
	ins = opcode << 27;
	ins |= (PCVM_INS_MODE_OP_REG_IMM << 24);
	ins |= reg << 20;
	ins |= imm;

	return ins;
}

/* | 5 : opcode | 3 : mode | 4 : reg1 | 4 : reg2 | 16 : -| */
unsigned pcasm::write_mode_op_reg_reg(unsigned opcode, unsigned reg1, unsigned reg2) {
	unsigned ins = 0;
	ins = opcode << 27;
	ins |= (PCVM_INS_MODE_OP_REG_REG << 24);
	ins |= reg1 << 20;
	ins |= reg2 << 16;

	return ins;
}

/* | 5 : opcode | 3 : mode | 4 : reg | 20 : imm | */
unsigned pcasm::write_mode_op_mem_imm(unsigned opcode, unsigned reg, unsigned imm) {
	unsigned ins = 0;
	ins = opcode << 27;
	ins |= (PCVM_INS_MODE_OP_MEM_IMM << 24);
	ins |= reg << 20;
	ins |= imm;

	return ins;
}

/* | 5 : opcode | 3 : mode | 4 : reg1 | 4 : reg2 | 16 : -| */
unsigned pcasm::write_mode_op_mem_reg(unsigned opcode, unsigned reg1, unsigned reg2) {
	unsigned ins = 0;
	ins = opcode << 27;
	ins |= (PCVM_INS_MODE_OP_MEM_REG << 24);
	ins |= reg1 << 20;
	ins |= reg2 << 16;

	return ins;
}

/* | 5 : opcode | 3 : mode | 4 : reg1 | 4 : reg2 | 16 : -| */
unsigned pcasm::write_mode_op_mem_mem(unsigned opcode, unsigned reg1, unsigned reg2) {
	unsigned ins = 0;
	ins = opcode << 27;
	ins |= (PCVM_INS_MODE_OP_MEM_MEM << 24);
	ins |= reg1 << 20;
	ins |= reg2 << 16;

	return ins;
}

bool pcasm::MOV_REG_LAB(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_REG);
	tokens.push_back(TOKEN_COMMA);
	tokens.push_back(TOKEN_REF_LABEL);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}

	pcasm_relocate rel;
	rel.type = PCASM_REL_FIXLST20B;
	rel.address = s_address;
	rel.symbol = _text_stack[2].str;
	s_relocates.push_back(rel);

	int ins = write_mode_op_reg_imm(opcode, _text_stack[0].reg, 0);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::MOV_MEM_LAB(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_LPARAM);
	tokens.push_back(TOKEN_REG);
	tokens.push_back(TOKEN_RPARAM);
	tokens.push_back(TOKEN_COMMA);
	tokens.push_back(TOKEN_REF_LABEL);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}

	pcasm_relocate rel;
	rel.type = PCASM_REL_FIXLST20B;
	rel.address = s_address;
	rel.symbol = _text_stack[4].str;
	s_relocates.push_back(rel);

	int ins = write_mode_op_mem_imm(opcode, _text_stack[1].reg, 0);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::MOV_REG_IMM(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_REG);
	tokens.push_back(TOKEN_COMMA);
	tokens.push_back(TOKEN_IMM);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}
	
	int ins = write_mode_op_reg_imm(opcode, _text_stack[0].reg, _text_stack[2].imm);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::MOV_REG_REG(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_REG);
	tokens.push_back(TOKEN_COMMA);
	tokens.push_back(TOKEN_REG);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}
	int ins = write_mode_op_reg_reg(opcode, _text_stack[0].reg, _text_stack[2].reg);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::MOV_MEM_IMM(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_LPARAM);
	tokens.push_back(TOKEN_REG);
	tokens.push_back(TOKEN_RPARAM);
	tokens.push_back(TOKEN_COMMA);
	tokens.push_back(TOKEN_IMM);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}
	int ins = write_mode_op_mem_imm(opcode, _text_stack[1].reg, _text_stack[4].imm);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::MOV_MEM_REG(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_LPARAM);
	tokens.push_back(TOKEN_REG);
	tokens.push_back(TOKEN_RPARAM);
	tokens.push_back(TOKEN_COMMA);
	tokens.push_back(TOKEN_REG);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}
	int ins = write_mode_op_mem_reg(opcode, _text_stack[1].reg, _text_stack[4].reg);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::MOV_MEM_MEM(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_LPARAM);
	tokens.push_back(TOKEN_REG);
	tokens.push_back(TOKEN_RPARAM);
	tokens.push_back(TOKEN_COMMA);
	tokens.push_back(TOKEN_LPARAM);
	tokens.push_back(TOKEN_REG);
	tokens.push_back(TOKEN_RPARAM);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}
	int ins = write_mode_op_mem_mem(opcode, _text_stack[1].reg, _text_stack[5].reg);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::cMOV(std::vector<unsigned char> &bytecodes)
{
	if (MOV_REG_IMM(PCVM_OP_MOV, bytecodes) || 
		MOV_REG_REG(PCVM_OP_MOV, bytecodes) || 
		MOV_MEM_IMM(PCVM_OP_MOV, bytecodes) ||
		MOV_MEM_REG(PCVM_OP_MOV, bytecodes) || 
		MOV_MEM_MEM(PCVM_OP_MOV, bytecodes) || 
		MOV_REG_LAB(PCVM_OP_MOV, bytecodes) ||
		MOV_MEM_LAB(PCVM_OP_MOV, bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::PUSH_LAB(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_REF_LABEL);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}

	pcasm_relocate rel;
	rel.type = PCASM_REL_FIXLST20B;
	rel.address = s_address;
	rel.symbol = _text_stack[0].str;
	s_relocates.push_back(rel);

	int ins = write_mode_op_imm(opcode, 0);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::PUSH_IMM(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_IMM);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}
	int ins = write_mode_op_imm(opcode, _text_stack[0].imm);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::PUSH_REG(unsigned opcode, std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_REG);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}
	int ins = write_mode_op_reg(opcode, _text_stack[0].reg);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::cPUSH(std::vector<unsigned char> &bytecodes)
{
	if (PUSH_IMM(PCVM_OP_PUSH, bytecodes) || 
		PUSH_REG(PCVM_OP_PUSH, bytecodes) ||
		PUSH_LAB(PCVM_OP_PUSH, bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::POP_REG(std::vector<unsigned char> &bytecodes)
{
	std::vector<int> tokens;
	tokens.push_back(TOKEN_REG);
	if (match(tokens) == false) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}
	int ins = write_mode_op_reg(PCVM_OP_POP, _text_stack[0].reg);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::cPOP(std::vector<unsigned char> &bytecodes)
{
	if (POP_REG(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::CMP_REG_IMM(std::vector<unsigned char> &bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_CMP, bytecodes);
}

bool pcasm::CMP_REG_REG(std::vector<unsigned char> &bytecodes)
{
	return MOV_REG_REG(PCVM_OP_CMP, bytecodes);
}

bool pcasm::CMP_MEM_IMM(std::vector<unsigned char> &bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_CMP, bytecodes);
}

bool pcasm::CMP_MEM_REG(std::vector<unsigned char> &bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_CMP, bytecodes);
}

bool pcasm::CMP_MEM_MEM(std::vector<unsigned char> &bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_CMP, bytecodes);
}

bool pcasm::cCMP(std::vector<unsigned char> &bytecodes)
{
	if (CMP_REG_IMM(bytecodes) || 
		CMP_REG_REG(bytecodes) || 
		CMP_MEM_IMM(bytecodes) ||
		CMP_MEM_REG(bytecodes) || 
		CMP_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::CALL_LAB(std::vector<unsigned char>& bytecodes)
{
	return PUSH_LAB(PCVM_OP_CALL, bytecodes);
}

bool pcasm::CALL_IMM(std::vector<unsigned char>& bytecodes)
{
	return PUSH_IMM(PCVM_OP_CALL, bytecodes);
}

bool pcasm::CALL_REG(std::vector<unsigned char>& bytecodes)
{
	return PUSH_REG(PCVM_OP_CALL, bytecodes);
}

bool pcasm::cCALL(std::vector<unsigned char>& bytecodes)
{
	if (CALL_IMM(bytecodes) || CALL_REG(bytecodes) || CALL_LAB(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::cRET(std::vector<unsigned char>& bytecodes)
{
	int ins = write_mode_op(PCVM_OP_RET);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::JMP_LAB(std::vector<unsigned char> &bytecodes)
{
	return PUSH_LAB(PCVM_OP_JMP, bytecodes);
}

bool pcasm::JMP_IMM(std::vector<unsigned char> &bytecodes)
{
	return PUSH_IMM(PCVM_OP_JMP, bytecodes);
}

bool pcasm::JMP_REG(std::vector<unsigned char> &bytecodes)
{
	return PUSH_REG(PCVM_OP_JMP, bytecodes);
}

bool pcasm::cJMP(std::vector<unsigned char> &bytecodes)
{
	if (JMP_IMM(bytecodes) || JMP_REG(bytecodes) || JMP_LAB(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::JE_LAB(std::vector<unsigned char> &bytecodes)
{
	return PUSH_LAB(PCVM_OP_JE, bytecodes);
}

bool pcasm::JE_IMM(std::vector<unsigned char> &bytecodes)
{
	return PUSH_IMM(PCVM_OP_JE, bytecodes);
}

bool pcasm::JE_REG(std::vector<unsigned char> &bytecodes)
{
	return PUSH_REG(PCVM_OP_JE, bytecodes);
}

bool pcasm::cJE(std::vector<unsigned char> &bytecodes)
{
	if (JE_IMM(bytecodes) || JE_REG(bytecodes) || JE_LAB(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::JNE_LAB(std::vector<unsigned char> &bytecodes)
{
	return PUSH_LAB(PCVM_OP_JNE, bytecodes);
}

bool pcasm::JNE_IMM(std::vector<unsigned char> &bytecodes)
{
	return PUSH_IMM(PCVM_OP_JNE, bytecodes);
}

bool pcasm::JNE_REG(std::vector<unsigned char> &bytecodes)
{
	return PUSH_REG(PCVM_OP_JNE, bytecodes);
}

bool pcasm::cJNE(std::vector<unsigned char> &bytecodes)
{
	if (JNE_IMM(bytecodes) || JNE_REG(bytecodes) || JNE_LAB(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::JB_LAB(std::vector<unsigned char> &bytecodes)
{
	return PUSH_LAB(PCVM_OP_JB, bytecodes);
}

bool pcasm::JB_IMM(std::vector<unsigned char> &bytecodes)
{
	return PUSH_IMM(PCVM_OP_JB, bytecodes);
}

bool pcasm::JB_REG(std::vector<unsigned char> &bytecodes)
{
	return PUSH_REG(PCVM_OP_JB, bytecodes);
}

bool pcasm::cJB(std::vector<unsigned char> &bytecodes)
{
	if (JB_IMM(bytecodes) || JB_REG(bytecodes) || JB_LAB(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::JA_LAB(std::vector<unsigned char> &bytecodes)
{
	return PUSH_LAB(PCVM_OP_JA, bytecodes);
}

bool pcasm::JA_IMM(std::vector<unsigned char> &bytecodes)
{
	return PUSH_IMM(PCVM_OP_JA, bytecodes);
}

bool pcasm::JA_REG(std::vector<unsigned char> &bytecodes)
{
	return PUSH_REG(PCVM_OP_JA, bytecodes);
}

bool pcasm::cJA(std::vector<unsigned char> &bytecodes)
{
	if (JA_IMM(bytecodes) || JA_REG(bytecodes) || JA_LAB(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::JBE_LAB(std::vector<unsigned char> &bytecodes)
{
	return PUSH_LAB(PCVM_OP_JBE, bytecodes);
}

bool pcasm::JBE_IMM(std::vector<unsigned char> &bytecodes)
{
	return PUSH_IMM(PCVM_OP_JBE, bytecodes);
}

bool pcasm::JBE_REG(std::vector<unsigned char> &bytecodes)
{
	return PUSH_REG(PCVM_OP_JBE, bytecodes);
}

bool pcasm::cJBE(std::vector<unsigned char> &bytecodes)
{
	if (JBE_IMM(bytecodes) || JBE_REG(bytecodes) || JBE_LAB(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::JAE_LAB(std::vector<unsigned char> &bytecodes)
{
	return PUSH_LAB(PCVM_OP_JAE, bytecodes);
}

bool pcasm::JAE_IMM(std::vector<unsigned char> &bytecodes)
{
	return PUSH_IMM(PCVM_OP_JAE, bytecodes);
}

bool pcasm::JAE_REG(std::vector<unsigned char> &bytecodes)
{
	return PUSH_REG(PCVM_OP_JAE, bytecodes);
}

bool pcasm::cJAE(std::vector<unsigned char> &bytecodes)
{
	if (JAE_IMM(bytecodes) || JAE_REG(bytecodes) || JAE_LAB(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::AND_REG_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_REG_LAB(PCVM_OP_AND, bytecodes);
}

bool pcasm::AND_MEM_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_MEM_LAB(PCVM_OP_AND, bytecodes);
}

bool pcasm::AND_REG_IMM(std::vector<unsigned char> &bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_AND, bytecodes);
}

bool pcasm::AND_REG_REG(std::vector<unsigned char> &bytecodes)
{
	return MOV_REG_REG(PCVM_OP_AND, bytecodes);
}

bool pcasm::AND_MEM_IMM(std::vector<unsigned char> &bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_AND, bytecodes);
}

bool pcasm::AND_MEM_REG(std::vector<unsigned char> &bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_AND, bytecodes);
}

bool pcasm::AND_MEM_MEM(std::vector<unsigned char> &bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_AND, bytecodes);
}

bool pcasm::cAND(std::vector<unsigned char> &bytecodes)
{
	if (AND_REG_LAB(bytecodes) ||
    AND_MEM_LAB(bytecodes) ||
    AND_REG_IMM(bytecodes) ||
		AND_REG_REG(bytecodes) || 
		AND_MEM_IMM(bytecodes) ||
		AND_MEM_REG(bytecodes) || 
		AND_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::OR_REG_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_REG_LAB(PCVM_OP_OR, bytecodes);
}

bool pcasm::OR_MEM_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_MEM_LAB(PCVM_OP_OR, bytecodes);
}

bool pcasm::OR_REG_IMM(std::vector<unsigned char> &bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_OR, bytecodes);
}

bool pcasm::OR_REG_REG(std::vector<unsigned char> &bytecodes)
{
	return MOV_REG_REG(PCVM_OP_OR, bytecodes);
}

bool pcasm::OR_MEM_IMM(std::vector<unsigned char> &bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_OR, bytecodes);
}

bool pcasm::OR_MEM_REG(std::vector<unsigned char> &bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_OR, bytecodes);
}

bool pcasm::OR_MEM_MEM(std::vector<unsigned char> &bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_OR, bytecodes);
}

bool pcasm::cOR(std::vector<unsigned char> &bytecodes)
{
	if (OR_REG_LAB(bytecodes) ||
    OR_MEM_LAB(bytecodes) ||
    OR_REG_IMM(bytecodes) ||
		OR_REG_REG(bytecodes) || 
		OR_MEM_IMM(bytecodes) ||
		OR_MEM_REG(bytecodes) || 
		OR_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::NOT_REG(std::vector<unsigned char> &bytecodes)
{
	return PUSH_REG(PCVM_OP_NOT, bytecodes);
}

bool pcasm::cNOT(std::vector<unsigned char> &bytecodes)
{
	return NOT_REG(bytecodes);
}

bool pcasm::ADD_REG_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_REG_LAB(PCVM_OP_ADD, bytecodes);
}

bool pcasm::ADD_MEM_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_MEM_LAB(PCVM_OP_ADD, bytecodes);
}

bool pcasm::ADD_REG_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_ADD, bytecodes);
}

bool pcasm::ADD_REG_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_REG(PCVM_OP_ADD, bytecodes);
}

bool pcasm::ADD_MEM_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_ADD, bytecodes);
}

bool pcasm::ADD_MEM_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_ADD, bytecodes);
}

bool pcasm::ADD_MEM_MEM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_ADD, bytecodes);
}

bool pcasm::cADD(std::vector<unsigned char>& bytecodes)
{
	if (ADD_REG_LAB(bytecodes) ||
    ADD_MEM_LAB(bytecodes) ||
    ADD_REG_IMM(bytecodes) ||
		ADD_REG_REG(bytecodes) ||
		ADD_MEM_IMM(bytecodes) ||
		ADD_MEM_REG(bytecodes) ||
		ADD_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::SUB_REG_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_REG_LAB(PCVM_OP_SUB, bytecodes);
}

bool pcasm::SUB_MEM_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_MEM_LAB(PCVM_OP_SUB, bytecodes);
}

bool pcasm::SUB_REG_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_SUB, bytecodes);
}

bool pcasm::SUB_REG_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_REG(PCVM_OP_SUB, bytecodes);
}

bool pcasm::SUB_MEM_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_SUB, bytecodes);
}

bool pcasm::SUB_MEM_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_SUB, bytecodes);
}

bool pcasm::SUB_MEM_MEM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_SUB, bytecodes);
}

bool pcasm::cSUB(std::vector<unsigned char>& bytecodes)
{
	if (SUB_REG_LAB(bytecodes) ||
    SUB_MEM_LAB(bytecodes) ||
    SUB_REG_IMM(bytecodes) ||
		SUB_REG_REG(bytecodes) ||
		SUB_MEM_IMM(bytecodes) ||
		SUB_MEM_REG(bytecodes) ||
		SUB_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::MUL_REG_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_REG_LAB(PCVM_OP_MUL, bytecodes);
}

bool pcasm::MUL_MEM_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_MEM_LAB(PCVM_OP_MUL, bytecodes);
}

bool pcasm::MUL_REG_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_MUL, bytecodes);
}

bool pcasm::MUL_REG_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_REG(PCVM_OP_MUL, bytecodes);
}

bool pcasm::MUL_MEM_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_MUL, bytecodes);
}

bool pcasm::MUL_MEM_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_MUL, bytecodes);
}

bool pcasm::MUL_MEM_MEM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_MUL, bytecodes);
}

bool pcasm::cMUL(std::vector<unsigned char>& bytecodes)
{
	if (MUL_REG_LAB(bytecodes) ||
    MUL_MEM_LAB(bytecodes) ||
    MUL_REG_IMM(bytecodes) ||
		MUL_REG_REG(bytecodes) ||
		MUL_MEM_IMM(bytecodes) ||
		MUL_MEM_REG(bytecodes) ||
		MUL_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::DIV_REG_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_REG_LAB(PCVM_OP_DIV, bytecodes);
}

bool pcasm::DIV_MEM_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_MEM_LAB(PCVM_OP_DIV, bytecodes);
}

bool pcasm::DIV_REG_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_DIV, bytecodes);
}

bool pcasm::DIV_REG_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_REG(PCVM_OP_DIV, bytecodes);
}

bool pcasm::DIV_MEM_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_DIV, bytecodes);
}

bool pcasm::DIV_MEM_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_DIV, bytecodes);
}

bool pcasm::DIV_MEM_MEM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_DIV, bytecodes);
}

bool pcasm::cDIV(std::vector<unsigned char>& bytecodes)
{
	if (DIV_REG_LAB(bytecodes) ||
    DIV_MEM_LAB(bytecodes) ||
    DIV_REG_IMM(bytecodes) ||
		DIV_REG_REG(bytecodes) ||
		DIV_MEM_IMM(bytecodes) ||
		DIV_MEM_REG(bytecodes) ||
		DIV_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::MOD_REG_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_REG_LAB(PCVM_OP_MOD, bytecodes);
}

bool pcasm::MOD_MEM_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_MEM_LAB(PCVM_OP_MOD, bytecodes);
}

bool pcasm::MOD_REG_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_MOD, bytecodes);
}

bool pcasm::MOD_REG_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_REG(PCVM_OP_MOD, bytecodes);
}

bool pcasm::MOD_MEM_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_MOD, bytecodes);
}

bool pcasm::MOD_MEM_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_MOD, bytecodes);
}

bool pcasm::MOD_MEM_MEM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_MOD, bytecodes);
}

bool pcasm::cMOD(std::vector<unsigned char>& bytecodes)
{
	if (MOD_REG_LAB(bytecodes) ||
    MOD_MEM_LAB(bytecodes) ||
    MOD_REG_IMM(bytecodes) ||
		MOD_REG_REG(bytecodes) ||
		MOD_MEM_IMM(bytecodes) ||
		MOD_MEM_REG(bytecodes) ||
		MOD_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::SHL_REG_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_REG_LAB(PCVM_OP_SHL, bytecodes);
}

bool pcasm::SHL_MEM_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_MEM_LAB(PCVM_OP_SHL, bytecodes);
}

bool pcasm::SHL_REG_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_SHL, bytecodes);
}

bool pcasm::SHL_REG_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_REG(PCVM_OP_SHL, bytecodes);
}

bool pcasm::SHL_MEM_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_SHL, bytecodes);
}

bool pcasm::SHL_MEM_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_SHL, bytecodes);
}

bool pcasm::SHL_MEM_MEM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_SHL, bytecodes);
}

bool pcasm::cSHL(std::vector<unsigned char>& bytecodes)
{
	if (SHL_REG_LAB(bytecodes) ||
    SHL_MEM_LAB(bytecodes) ||
    SHL_REG_IMM(bytecodes) ||
		SHL_REG_REG(bytecodes) ||
		SHL_MEM_IMM(bytecodes) ||
		SHL_MEM_REG(bytecodes) ||
		SHL_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::SHR_REG_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_REG_LAB(PCVM_OP_SHR, bytecodes);
}

bool pcasm::SHR_MEM_LAB(std::vector<unsigned char> &bytecodes) {
  return MOV_MEM_LAB(PCVM_OP_SHR, bytecodes);
}

bool pcasm::SHR_REG_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_IMM(PCVM_OP_SHR, bytecodes);
}

bool pcasm::SHR_REG_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_REG_REG(PCVM_OP_SHR, bytecodes);
}

bool pcasm::SHR_MEM_IMM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_IMM(PCVM_OP_SHR, bytecodes);
}

bool pcasm::SHR_MEM_REG(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_REG(PCVM_OP_SHR, bytecodes);
}

bool pcasm::SHR_MEM_MEM(std::vector<unsigned char>& bytecodes)
{
	return MOV_MEM_MEM(PCVM_OP_SHR, bytecodes);
}

bool pcasm::cSHR(std::vector<unsigned char>& bytecodes)
{
	if (SHR_REG_LAB(bytecodes) ||
    SHR_MEM_LAB(bytecodes) ||
    SHR_REG_IMM(bytecodes) ||
    SHR_REG_REG(bytecodes) ||
    SHR_MEM_IMM(bytecodes) ||
		SHR_MEM_REG(bytecodes) ||
		SHR_MEM_MEM(bytecodes)) {
		return true;
	}
	return false;
}

bool pcasm::INT_IMM(std::vector<unsigned char> &bytecodes)
{
	return PUSH_IMM(PCVM_OP_INT, bytecodes);
}

bool pcasm::cINT(std::vector<unsigned char> &bytecodes)
{
	return INT_IMM(bytecodes);
}

bool pcasm::cNOP(std::vector<unsigned char> &bytecodes)
{
	int ins = write_mode_op(PCVM_OP_NOP);
	write_ins(ins, bytecodes);
	return true;
}

bool pcasm::cInclude(std::vector<unsigned char> &bytecodes)
{
	pcasm_token token;
	token = next_token();
	if (token.token != TOKEN_STRING) {
		_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
		return false;
	}

	/* not found */
	if (s_sources.find(token.text.str) == s_sources.end()) {
		s_sources[token.text.str] = std::shared_ptr<pcasm>(new pcasm());
		if (s_sources[token.text.str] == nullptr) {
			_error = PCASM_ERROR_ALLOC_MEMORY;
			return false;
		}
		if (s_sources[token.text.str]->make(token.text.str, bytecodes) == false) {
			_error = s_sources[token.text.str]->error();
			_errstr = token.text.str;
			return false;
		}
	}

	return true;
}

bool pcasm::cDefLabel(pcasm_token &token)
{
	/* not found symbol, then create it */
	if (s_symbols.find(token.text.str) == s_symbols.end()) {
		s_symbols[token.text.str] = std::shared_ptr<pcasm_label>(new pcasm_label);
		if (s_symbols[token.text.str] == nullptr) {
			_error = PCASM_ERROR_ALLOC_MEMORY;
			_errstr = token.text.str;
			return false;
		}
		s_symbols[token.text.str]->mode_address = _address;
		s_symbols[token.text.str]->address = s_address;
	}
	/* symbol has existed */
	else {
		_error = PCASM_ERROR_SYNTAX_SAME_LABEL;
		return false;
	}
	return true;
}

bool pcasm::pass1()
{
	pcasm_token token;
	_token_source.clear();
	do {
		if (scanner(token) == false) {
			return false;
		}
		_token_source.push_back(token);
	} while (token.token != TOKEN_EOF);
	return true;
}

bool pcasm::pass2(std::vector<unsigned char> &bytecodes)
{
	if (parser(bytecodes) == false) return false;
	return true;
}

bool pcasm::scanner(pcasm_token &token)
{
	int c = 0;
	std::string str;
	while (teste() == false) {
		c = readc();
		if ((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n')) {
			continue;
		}
		else if (c == ';') {
			do {
				c = readc();
				if (c == -1) {
					token.token = TOKEN_EOF;
					return true;
				}
			} while (c != '\n');
			continue;
		}

		switch (c) {
		case 'x':
			str.clear();
			do {
				c = readc();
				if (s_is_hexchar(c) == false) {
					decp();
					break;
				}
				str.push_back(c);
			} while (true);

			if (str.empty() == false) {
				char *hexptr = nullptr;
				token.text.imm = static_cast<unsigned>(strtol(str.c_str(), &hexptr, 16));
				token.token = TOKEN_IMM;
				return true;
			}
			else {
				_error = PCASM_ERROR_SCAN_INVALID_CHAR;
				return false;
			}
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			str.clear();
			str.push_back(c);
			do {
				c = readc();
				if ((c < '0') || (c > '9')) {
					decp();
					break;
				}
				str.push_back(c);
			} while (true);
			token.text.imm = static_cast<unsigned>(atol(str.c_str()));
			token.token = TOKEN_IMM;
			return true;
		case 'm':
			decp();
			if (_source.substr(_pos, 3) == "mov") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_MOV;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "mul") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_MUL;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "mod") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_MOD;
				token.token = TOKEN_OP;
				return true;
      }
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 'd':
			decp();
			if (_source.substr(_pos, 3) == "div") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_DIV;
				token.token = TOKEN_OP;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 'p':
			decp();
			if (_source.substr(_pos, 4) == "push") {
				if (plusp(4) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_PUSH;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "pop") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_POP;
				token.token = TOKEN_OP;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 'c':
			decp();
			if (_source.substr(_pos, 3) == "cmp") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_CMP;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 4) == "call") {
				if (plusp(4) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_CALL;
				token.token = TOKEN_OP;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 'j':
			decp();
			if (_source.substr(_pos, 3) == "jmp") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_JMP;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 2) == "je") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_JE;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "jne") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_JNE;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 2) == "jb") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_JB;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 2) == "ja") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_JA;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "jbe") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_JBE;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "jae") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_JAE;
				token.token = TOKEN_OP;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 'a':
			decp();
			if (_source.substr(_pos, 3) == "and") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_AND;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "add") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_ADD;
				token.token = TOKEN_OP;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 'o':
			decp();
			if (_source.substr(_pos, 2) == "or") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_OR;
				token.token = TOKEN_OP;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 'n':
			decp();
			if (_source.substr(_pos, 3) == "not") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_NOT;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "nop") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_NOP;
				token.token = TOKEN_OP;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 'i':
			decp();
			if (_source.substr(_pos, 3) == "int") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_INT;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 2) == "ip") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_IP;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 7) == "include") {
				if (plusp(7) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.token = TOKEN_INCLUDE;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 'r':
			decp();
			if (_source.substr(_pos, 3) == "ret") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_RET;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r0") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_IP;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r2") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_SP;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r3") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_RET;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r4") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R4;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r5") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R5;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r6") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R6;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r7") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R7;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r8") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R8;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r9") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R9;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 3) == "r10") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R10;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 3) == "r11") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R11;
				token.token = TOKEN_REG;
				return true;
			} 
			else if (_source.substr(_pos, 3) == "r12") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R12;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 3) == "r13") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R13;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 3) == "r14") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R14;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 3) == "r15") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_R15;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "r1") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_SB;
				token.token = TOKEN_REG;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case 's':
			decp();
			if (_source.substr(_pos, 2) == "sb") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_SB;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 2) == "sp") {
				if (plusp(2) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.reg = PCVM_REG_SP;
				token.token = TOKEN_REG;
				return true;
			}
			else if (_source.substr(_pos, 3) == "sub") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_SUB;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "shl") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_SHL;
				token.token = TOKEN_OP;
				return true;
			}
			else if (_source.substr(_pos, 3) == "shr") {
				if (plusp(3) == false) {
					_error = PCASM_ERROR_SCAN_INVALID_CHAR;
					return false;
				}
				token.text.opcode = PCVM_OP_SHR;
				token.token = TOKEN_OP;
				return true;
			}
      else {
        _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN;
        return false;
      }
			break;
		case ':':
			token.token = TOKEN_COLON;
			return true;
		case ',':
			token.token = TOKEN_COMMA;
			return true;
		case '"':
			token.text.str.clear();
			do {
				c = readc();
				if (c == -1) {
					_error = PCASM_ERROR_SCAN_QUOTATION_NOT_CLOSE;
					return false;
				}
				token.text.str.push_back(c);
			} while (c != '"');
			token.text.str.pop_back();
			token.token = TOKEN_STRING;
			return true;
		case '[':
			token.token = TOKEN_LPARAM;
			return true;
		case ']':
			token.token = TOKEN_RPARAM;
			return true;
		case '@':
			token.text.str.clear();
			c = readc();
			if (c == -1) {
				_error = PCASM_ERROR_SCAN_QUOTATION_NOT_CLOSE;
				return false;
			}
			if ((isalpha(c)) || (c == '_')) {
				int len = 1;
				while ((c == '_') || isalnum(c)) {
					if (len >= PCASM_MAX_LABEL) {
						_error = PCASM_ERROR_SCAN_LABNAME_OVER_LIMIT;
						_errstr = token.text.str;
						return false;
					}
					token.text.str.push_back(c);
					c = readc();
					len++;
				}

				if (c == ':') {
					token.token = TOKEN_DEF_LABEL;
					return true;
				}
				else {
          token.token = TOKEN_REF_LABEL;
          return true;
				}
			}
			break;
		default:
      _error = PCASM_ERROR_SCAN_NOT_MATCH_TOKEN_START_CHAR;
      return false;
		}
	}

	token.token = TOKEN_EOF;
	return true;
}

//static size_t s_imm_size(unsigned imm) {
//	if (imm <= 0xFF) {
//		return 1;
//	}
//	else if (imm <= 0xFFFF) {
//		return 2;
//	}
//
//	return 4;
//}

bool pcasm::parser(std::vector<unsigned char> &bytecodes)
{
	pcasm_token token;
	do {
		token = next_token();
		if (token.token == TOKEN_EOF) {
			break;
		}
		else if (token.token == TOKEN_OP) {
			if ((this->*_handles[token.text.opcode])(bytecodes) == false)
        return false;
			if (plus_address() == false) return false;
		}
		else if (token.token == TOKEN_INCLUDE) {
			if (cInclude(bytecodes) == false)
        return false;
		}
		else if (token.token == TOKEN_DEF_LABEL) {
			if (cDefLabel(token) == false)
        return false;
		}
		else if (token.token == TOKEN_IMM) {
			if (plus_address(write_imm(token.text.imm, bytecodes)) == false)
        return false;
		}
		else if (token.token == TOKEN_STRING) {
			if (plus_address(write_string(token.text.str, bytecodes)) == false)
        return false;
		}
		else {
			_error = PCASM_ERROR_SYNTAX_INCONFORMITY_TOKEN;
			return false;
		}
	} while (true);
	return true;
}

void pcasm::set_error(int err)
{
	_error = err;
}

bool pcasm::match(std::vector<int> tokens)
{
	pcasm_token token;
	_text_stack.clear();
	_err_on_token = TOKEN_NUMBER;
	if (tokens.empty()) return false;
	int count = 0;
	for (auto t : tokens) {
		count++;
		token = next_token();
		if (token.token == t) {
			_text_stack.push_back(token.text);
		}
		else {
			rollback_token(count);
			_text_stack.clear();
			_error = PCASM_ERROR_SYNTAX_NOT_MATCH_TOKEN;
			_err_on_token = t;
			return false;
		}
	}

	return true;
}

bool pcasm::plus_address(unsigned plus)
{
	if (s_address >= (1024 * 1024)) {
		_error = PCASM_ERROR_CODE_OVER_LIMIT;
		return false;
	}

	_address += plus;
	s_address += plus;
	return true;
}

bool pcasm::teste()
{
	return (_pos >= _source.size());
}

int pcasm::readc()
{
	if (_pos >= _source.size()) {
		return -1;
	}
	return _source[_pos++];
}

bool pcasm::plusp(int plus)
{
	if (_pos + plus > _source.size())
		return false;
	_pos += plus;
	return true;
}

bool pcasm::decp(int dec)
{
	if (_pos - dec < 0)
		return false;
	_pos -= dec;
	return true;
}

int pcasm::write_ins(int ins, std::vector<unsigned char> &bytecodes)
{
	unsigned char *ptr = reinterpret_cast<unsigned char*>(&ins);
	for (int i = 0; i < sizeof(int); i++) {
		bytecodes.push_back(*ptr++);
	}
	return sizeof(int);
}

int pcasm::write_imm(unsigned data, std::vector<unsigned char> &bytecodes)
{
	unsigned char *ptr = reinterpret_cast<unsigned char*>(&data);
	for (int i = 0; i < sizeof(int); i++) {
		bytecodes.push_back(*ptr++);
	}
	return sizeof(unsigned);
}

int pcasm::write_datas(const std::vector<unsigned char>& datas, std::vector<unsigned char> &bytecodes)
{
	for (auto c : datas) {
		bytecodes.push_back(c);
	}

	int s1 = datas.size();
	int s2 = s_up4(s1);
	if (s2 > s1) {
		s1 = s2 - s1;
		while (s1--) {
			bytecodes.push_back(0);
		}
	}

	return s2;
}

int pcasm::write_string(const std::string &str, std::vector<unsigned char> &bytecodes) {
	for (auto c : str) {
		bytecodes.push_back(c);
	}

	int s1 = str.size();
	int s2 = s_up4(s1);
	if (s2 > s1) {
		s1 = s2 - s1;
		while (s1--) {
			bytecodes.push_back(0);
		}
	}

	return s2;
}

/* end return false */
pcasm_token pcasm::next_token()
{
	if (_token_source.empty()) {
		pcasm_token token;
		token.token = TOKEN_NUMBER;
		return token;
	}

	return _token_source[_token_pos++];
}

void pcasm::rollback_token(int num)
{
	if (_token_pos - num < 0) _token_pos = 0;
	else _token_pos -= num;
}