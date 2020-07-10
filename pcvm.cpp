#include <pcvm.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>

#include <string>

static size_t s_up4(size_t v) {
  return ~3u & (3 + v);
}

pcvm::pcvm() : _space(nullptr)
{
  reset();
  
  _handles[PCVM_OP_MOV] = &pcvm::iMOV;
  _handles[PCVM_OP_PUSH] = &pcvm::iPUSH;
  _handles[PCVM_OP_POP] = &pcvm::iPOP;
  _handles[PCVM_OP_CMP] = &pcvm::iCMP;
  _handles[PCVM_OP_CALL] = &pcvm::iCALL;
  _handles[PCVM_OP_RET] = &pcvm::iRET;
  _handles[PCVM_OP_JMP] = &pcvm::iJMP;
  _handles[PCVM_OP_JE] = &pcvm::iJE;
  _handles[PCVM_OP_JNE] = &pcvm::iJNE;
  _handles[PCVM_OP_JB] = &pcvm::iJB;
  _handles[PCVM_OP_JA] = &pcvm::iJA;
  _handles[PCVM_OP_JBE] = &pcvm::iJBE;
  _handles[PCVM_OP_JAE] = &pcvm::iJAE;
  _handles[PCVM_OP_AND] = &pcvm::iAND;
  _handles[PCVM_OP_OR] = &pcvm::iOR;
  _handles[PCVM_OP_NOT] = &pcvm::iNOT;
  _handles[PCVM_OP_ADD] = &pcvm::iADD;
  _handles[PCVM_OP_SUB] = &pcvm::iSUB;
  _handles[PCVM_OP_MUL] = &pcvm::iMUL;
  _handles[PCVM_OP_DIV] = &pcvm::iDIV;
  _handles[PCVM_OP_MOD] = &pcvm::iMOD;
  _handles[PCVM_OP_SHL] = &pcvm::iSHL;
  _handles[PCVM_OP_SHR] = &pcvm::iSHR;
  _handles[PCVM_OP_INT] = &pcvm::iINT;
  _handles[PCVM_OP_NOP] = &pcvm::iNOP;
  
  _is_big_endian = is_big_endian();
}

pcvm::~pcvm()
{
  if (_space) delete[] _space;
}

bool pcvm::is_big_endian() {
  short int test = 0x1234;
  if (*((char *)&test) == 0x12) return true;
  return false;
}

#ifdef SUPPORT_DEBUGER
bool pcvm::disasm_all(unsigned char *buf, size_t bufsize)
{
  unsigned *space = reinterpret_cast<unsigned *>(buf);
  size_t space_size = bufsize / sizeof(unsigned);
  std::string info;
  for (size_t i = 0; i < space_size; i++) {
    unsigned ins = *reinterpret_cast<unsigned*>(space + i);
    if (disasm(ins, info) == false) {
      return false;
    }
    
    printf("<0x%04lx>%s\r\n", i * sizeof(unsigned), info.c_str());
  }
  
  return true;
}
#endif

bool pcvm::run(const unsigned char *codes, size_t cs, unsigned entry_offset
#ifdef SUPPORT_DEBUGER
               , bool debug
#endif
) {
  assert(codes);
  assert(cs);
  
  reset();
  
  if (cs > _code_size)
  {
    _error = PCVM_ERROR_OVER_CODE_SIZE_LIMIT;
    return false;
  }
  
  _code_size = s_up4(cs);
  _stack_size = SPACE_SIZE - _code_size;
  _stack = _space + _code_size;
  
  memcpy(_code, codes, cs);
  /* 0->   ---------- <- codes + datas
   *       |        | <- ip
   *       |        |
   *       | codes  |
   *       |        |
   *       |        |
   *       |        |
   *       | datas  |
   *       |        |
   * cs->  ---------- <- stack
   *       |        | <- sp
   *       | stack  |
   *       |        |
   * 1024->---------- <- sb
   */
  
  _registers[PCVM_REG_IP] = entry_offset;
  
  unsigned ins = 0;
  while (_shutdown == false) {
    
#ifdef SUPPORT_DEBUGER
    if (debug) {
      debugger(_registers[PCVM_REG_IP]);
    }
#endif
    
    if (readi(ins) == false) {
      if (_error == PCVM_ERROR_OVER_CODE_SIZE_LIMIT) {
        _error = PCVM_ERROR_SUCCESS;
        return true;
      }
      return false;
    }
    if (call(ins) == false) return false;
  }
  
  return true;
}

bool pcvm::set_input_io(int io, unsigned char * stream)
{
  if (io >= PCVM_IO_INPUT_NUMBER) {
    _error = PCVM_ERROR_INVALID_IO_ACCESS;
    return false;
  }
  _io_input[io] = stream;
  return true;
}

bool pcvm::set_output_io(int io, unsigned char * stream)
{
  if (io >= PCVM_IO_OUTPUT_NUMBER) {
    _error = PCVM_ERROR_INVALID_IO_ACCESS;
    return false;
  }
  _io_output[io] = stream;
  return true;
}

bool pcvm::set_input_io_size(int io, size_t size) {
  if (io >= PCVM_IO_INPUT_NUMBER) {
    _error = PCVM_ERROR_INVALID_IO_ACCESS;
    return false;
  }
  _io_input_size[io] = size;
  return true;
}

bool pcvm::set_output_io_size(int io, size_t size) {
  if (io >= PCVM_IO_OUTPUT_NUMBER) {
    _error = PCVM_ERROR_INVALID_IO_ACCESS;
    return false;
  }
  _io_output_size[io] = size;
  return true;
}

unsigned char *pcvm::get_input_io(int io) {
  if (io >= PCVM_IO_INPUT_NUMBER) {
    _error = PCVM_ERROR_INVALID_IO_ACCESS;
    return nullptr;
  }
  return _io_input[io];
}

unsigned char *pcvm::get_output_io(int io) {
  if (io >= PCVM_IO_OUTPUT_NUMBER) {
    _error = PCVM_ERROR_INVALID_IO_ACCESS;
    return nullptr;
  }
  return _io_output[io];
}

size_t pcvm::get_input_io_size(int io) {
  if (io >= PCVM_IO_INPUT_NUMBER) {
    _error = PCVM_ERROR_INVALID_IO_ACCESS;
    return 0xFFFFFFFF;
  }
  return _io_input_size[io];
}

size_t pcvm::get_output_io_size(int io) {
  if (io >= PCVM_IO_INPUT_NUMBER) {
    _error = PCVM_ERROR_INVALID_IO_ACCESS;
    return 0xFFFFFFFF;
  }
  return _io_output_size[io];
}

int pcvm::error()
{
  return _error;
}

bool pcvm::call(unsigned ins)
{
  pcvm_ins_mode_op ins_mode;
  if (ins_2_mode_op(ins, ins_mode) == false) return false;
  
  unsigned char opcode = ins_mode.opcode;
  unsigned char mode = ins_mode.mode;
  if ((opcode >= PCVM_OP_MOV) && (opcode < PCVM_OP_NUMBER))
  {
    return (this->*_handles[opcode])(ins, mode);
  }
  _error = PCVM_ERROR_INVALID_OPCODE;
  return false;
}

bool pcvm::invalid_register(int i)
{
  if ((i >= 0) && (i < PCVM_REG_NUMBER)) return false;
  return true;
}

bool pcvm::registers(int i, unsigned &v, bool four)
{
  if ((i >= 0) && (i < PCVM_REG_NUMBER)) {
    
    if (four) {
      v = _registers[i];
      return true;
    }
    
    unsigned out = 0;
    if (read_memory(reinterpret_cast<unsigned char*>(&_registers[i]),
                    reinterpret_cast<unsigned char*>(&out)) == false) {
      v = 0;
      return false;
    }
    v = out;
    return true;
  }
  
  _error = PCVM_ERROR_INVALID_REGISTER;
  return false;
}

bool pcvm::set_registers(int i, unsigned r, bool four)
{
  if ((i >= 0) && (i < PCVM_REG_NUMBER)) {
    if (four) {
      _registers[i] = r;
      return true;
    }
    return write_memory(reinterpret_cast<unsigned char*>(&_registers[i]), r);
  }
  _error = PCVM_ERROR_INVALID_REGISTER;
  return false;
}

bool pcvm::read_memory(unsigned char *address, unsigned char *v) {
  if (_flags.A == 1) {
    *v = *address;
  }
  else if (_flags.A == 2) {
    *(unsigned short*)v = get_te16(address);
  }
  else if (_flags.A == 3) {
    *(unsigned int *)v = get_te32(address);
  }
  else {
    _error = PCVM_ERROR_INVALID_FLAG_A;
    return false;
  }
  return true;
}

bool pcvm::write_memory(unsigned char *address, unsigned v) {
  if (_flags.A == 1) {
    *address = (unsigned char)(v & 0xFF);
  }
  else if (_flags.A == 2) {
    set_te16(address, (unsigned short)(v & 0xFFFF));
  }
  else if (_flags.A == 3) {
    set_te32(address, v);
  }
  else {
    _error = PCVM_ERROR_INVALID_FLAG_A;
    return false;
  }
  return true;
}

bool pcvm::readi(unsigned & i)
{
  if (_registers[PCVM_REG_IP] >= _code_size) {
    _error = PCVM_ERROR_OVER_CODE_SIZE_LIMIT;
    return false;
  }
  i = *reinterpret_cast<unsigned*>(_code + _registers[PCVM_REG_IP]);
  _registers[PCVM_REG_IP] += sizeof(unsigned);
  return true;
}

bool pcvm::invalid_offset(unsigned off)
{
  if (off >= SPACE_SIZE) return true;
  return false;
}

bool pcvm::calc_address(unsigned off, unsigned **addr)
{
  if (invalid_offset(off)) {
    _error = PCVM_ERROR_INVALID_ADDRESS;
    return false;
  }
  
  *addr = reinterpret_cast<unsigned*>(_space + off);
  return true;
}

static unsigned short s_reverse_16_order(unsigned short v) {
  return ((v & 0xFF) << 8) | ((v & 0xFF00) >> 8);
}

static unsigned int s_reverse_32_order(unsigned int v) {
  return ((v & 0xFF) << 24) | ((v & 0xFF00) << 16) | ((v & 0xFF0000) >> 16) | ((v & 0xFF000000) >> 24);
}

unsigned short pcvm::get_te16(unsigned char *address) {
  assert(address);
  if (!_is_big_endian) return *reinterpret_cast<unsigned short*>(address);
  else return s_reverse_16_order(*reinterpret_cast<unsigned short*>(address));
}

unsigned int pcvm::get_te32(unsigned char *address) {
  assert(address);
  if (!_is_big_endian) return *reinterpret_cast<unsigned int*>(address);
  else return s_reverse_32_order(*reinterpret_cast<unsigned int*>(address));
}

void pcvm::set_te16(unsigned char *address, unsigned short v) {
  assert(address);
  if (!_is_big_endian) *reinterpret_cast<unsigned short*>(address) = v;
  else *reinterpret_cast<unsigned short*>(address) = s_reverse_16_order(v);
}

void pcvm::set_te32(unsigned char *address, unsigned v) {
  assert(address);
  if (!_is_big_endian) *reinterpret_cast<unsigned*>(address) = v;
  else *reinterpret_cast<unsigned*>(address) = s_reverse_32_order(v);
}

void pcvm::reset()
{
  memset(&_registers, 0, sizeof(unsigned) * PCVM_REG_NUMBER);
  memset(&_flags, 0, sizeof(pcvm_flags_register));
  _flags.A = 3;
  if (_space) delete[] _space;
  _space = new unsigned char[SPACE_SIZE];
  if (_space == nullptr) {
    _error = PCVM_ERROR_ALLOC_FAILED;
    return;
  }
  memset(_space, 0, SPACE_SIZE);
  
  /* default runtime size */
  _code_size = CODE_SIZE;
  _stack_size = STACK_SIZE;
  
  _code = _space;
  _stack = _space + _code_size;
  
  _registers[PCVM_REG_IP] = 0;
  _registers[PCVM_REG_SB] = SPACE_SIZE;
  _registers[PCVM_REG_SP] = SPACE_SIZE - sizeof(unsigned);
  
  _shutdown = false;
  _error = PCVM_ERROR_SUCCESS;
}

/* mov reg, imm
 * mov reg, reg
 * mov mem, imm
 * mov mem, reg
 * mov mem, mem
 */
bool pcvm::handle_ins_mode_op(unsigned ins, unsigned &op) {
  pcvm_ins_mode_op ins_mode;
  
  if (ins_2_mode_op(ins, ins_mode) == false) return false;
  op = ins_mode.opcode;
  return true;
}

bool pcvm::handle_ins_mode_op_imm(unsigned ins, unsigned &op, unsigned &imm) {
  pcvm_ins_mode_op_imm ins_mode;
  if (ins_2_mode_op_imm(ins, ins_mode) == false) return false;
  op = ins_mode.opcode;
  imm = ins_mode.imm;
  return true;
}

bool pcvm::handle_ins_mode_op_reg(unsigned ins, unsigned &op, unsigned &reg) {
  pcvm_ins_mode_op_reg ins_mode;
  if (ins_2_mode_op_reg(ins, ins_mode) == false) return false;
  op = ins_mode.opcode;
  reg = ins_mode.reg;
  return true;
}

bool pcvm::handle_ins_mode_op_reg_imm(unsigned ins, unsigned &op,
                                      unsigned &reg, unsigned &imm) {
  pcvm_ins_mode_op_reg_imm ins_mode;
  if (ins_2_mode_op_reg_imm(ins, ins_mode) == false) return false;
  op = ins_mode.opcode;
  reg = ins_mode.reg;
  imm = ins_mode.imm;
  return true;
}

bool pcvm::handle_ins_mode_op_reg_reg(unsigned ins, unsigned &op,
                                      unsigned &reg1, unsigned &reg2) {
  pcvm_ins_mode_op_reg_reg ins_mode;
  if (ins_2_mode_op_reg_reg(ins, ins_mode) == false) return false;
  op = ins_mode.opcode;
  reg1 = ins_mode.reg1;
  reg2 = ins_mode.reg2;
  return true;
}

bool pcvm::handle_ins_mode_op_mem_imm(unsigned ins, unsigned &op,
                                      unsigned **address, unsigned &imm) {
  pcvm_ins_mode_op_mem_imm ins_mode;
  if (ins_2_mode_op_mem_imm(ins, ins_mode) == false) return false;
  op = ins_mode.opcode;
  unsigned reg = ins_mode.reg;
  unsigned offset = 0;
  if (registers(reg, offset, true) == false) return false;
  if (calc_address(offset, address) == false) return false;
  imm = ins_mode.imm;
  return true;
}

bool pcvm::handle_ins_mode_op_mem_reg(unsigned ins, unsigned &op,
                                      unsigned **address, unsigned &reg) {
  pcvm_ins_mode_op_mem_reg ins_mode;
  if (ins_2_mode_op_mem_reg(ins, ins_mode) == false) return false;
  
  op = ins_mode.opcode;
  unsigned mem_reg = ins_mode.reg1;
  unsigned offset = 0;
  if (registers(mem_reg, offset, true) == false) return false;
  if (calc_address(offset, address) == false) return false;
  reg = ins_mode.reg2;
  return true;
}

bool pcvm::handle_ins_mode_op_mem_mem(unsigned ins, unsigned &op,
                                      unsigned **address1, unsigned **address2) {
  pcvm_ins_mode_op_mem_mem ins_mode;
  if (ins_2_mode_op_mem_mem(ins, ins_mode) == false) return false;
  op = ins_mode.opcode;
  unsigned reg1 = ins_mode.reg1;
  unsigned reg2 = ins_mode.reg2;
  unsigned offset1 = 0, offset2 = 0;
  
  if (registers(reg1, offset1, true) == false) return false;
  if (calc_address(offset1, address1) == false) return false;
  
  if (registers(reg2, offset2, true) == false) return false;
  if (calc_address(offset2, address2) == false) return false;
  
  return true;
}

bool pcvm::ins_2_opocde_mode(unsigned ins, unsigned & opcode, unsigned & mode)
{
  opcode = ins >> 27;
  mode = (ins >> 24) & 0x07;
  
  if (opcode >= PCVM_OP_NUMBER) {
    _error = PCVM_ERROR_INVALID_OPCODE;
    return false;
  }
  
  if (mode >= PCVM_INS_MODE_NUMBER) {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

/* | 5 : opcode | 3 : mode | 24 : -| */
bool pcvm::ins_2_mode_op(unsigned ins, pcvm_ins_mode_op & mode)
{
  unsigned op = 0, mod = 0;
  
  if (ins_2_opocde_mode(ins, op, mod) == false) return false;
  
  mode.opcode = op;
  mode.mode = mod;
  mode.reserve = 0;
  
  return true;
}

/* | 5 : opcode | 3 : mode | 4 : -| 20 : imm | */
bool pcvm::ins_2_mode_op_imm(unsigned ins, pcvm_ins_mode_op_imm & mode)
{
  unsigned op = 0, mod = 0;
  
  if (ins_2_opocde_mode(ins, op, mod) == false) return false;
  
  mode.opcode = op;
  mode.mode = mod;
  mode.imm = ins & 0xFFFFF;
  mode.reserve = 0;
  
  return true;
}

/* | 5 : opcode | 3 : mode | 4 : reg | 20 : -| */
bool pcvm::ins_2_mode_op_reg(unsigned ins, pcvm_ins_mode_op_reg & mode)
{
  unsigned op = 0, mod = 0;
  
  if (ins_2_opocde_mode(ins, op, mod) == false) return false;
  
  mode.opcode = op;
  mode.mode = mod;
  mode.reg = (ins >> 20) & 0x0F;
  mode.reserve = 0;
  
  return true;
}

/* | 5 : opcode | 3 : mode | 4 : reg | 20 : imm | */
bool pcvm::ins_2_mode_op_reg_imm(unsigned ins, pcvm_ins_mode_op_reg_imm & mode)
{
  unsigned op = 0, mod = 0;
  
  if (ins_2_opocde_mode(ins, op, mod) == false) return false;
  
  mode.opcode = op;
  mode.mode = mod;
  mode.reg = (ins >> 20) & 0x0F;
  mode.imm = ins & 0xFFFFF;
  
  return true;
}

/* | 5 : opcode | 3 : mode | 4 : reg1 | 4 : reg2 | 16 : -| */
bool pcvm::ins_2_mode_op_reg_reg(unsigned ins, pcvm_ins_mode_op_reg_reg & mode)
{
  unsigned op = 0, mod = 0;
  
  if (ins_2_opocde_mode(ins, op, mod) == false) return false;
  
  mode.opcode = op;
  mode.mode = mod;
  mode.reg1 = (ins >> 20) & 0x0F;
  mode.reg2 = (ins >> 16) & 0x0F;
  mode.reserve = 0;
  
  return true;
}
/* | 5 : opcode | 3 : mode | 4 : reg | 20 : imm | */
bool pcvm::ins_2_mode_op_mem_imm(unsigned ins, pcvm_ins_mode_op_mem_imm & mode)
{
  unsigned op = 0, mod = 0;
  
  if (ins_2_opocde_mode(ins, op, mod) == false) return false;
  
  mode.opcode = op;
  mode.mode = mod;
  mode.reg = (ins >> 20) & 0x0F;
  mode.imm = ins & 0xFFFFF;
  
  return true;
}

/* | 5 : opcode | 3 : mode | 4 : reg1 | 4 : reg2 | 16 : -| */
bool pcvm::ins_2_mode_op_mem_reg(unsigned ins, pcvm_ins_mode_op_mem_reg & mode)
{
  unsigned op = 0, mod = 0;
  
  if (ins_2_opocde_mode(ins, op, mod) == false) return false;
  
  mode.opcode = op;
  mode.mode = mod;
  mode.reg1 = (ins >> 20) & 0x0F;
  mode.reg2 = (ins >> 16) & 0x0F;
  mode.reserve = 0;
  
  return true;
}

/* | 5 : opcode | 3 : mode | 4 : reg1 | 4 : reg2 | 16 : -| */
bool pcvm::ins_2_mode_op_mem_mem(unsigned ins, pcvm_ins_mode_op_mem_mem & mode)
{
  unsigned op = 0, mod = 0;
  
  if (ins_2_opocde_mode(ins, op, mod) == false) return false;
  
  mode.opcode = op;
  mode.mode = mod;
  mode.reg1 = (ins >> 20) & 0x0F;
  mode.reg2 = (ins >> 16) & 0x0F;
  mode.reserve = 0;
  
  return true;
}

bool pcvm::iMOV(unsigned ins, unsigned mode)
{
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    return set_registers(reg, imm);
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    unsigned v = 0;
    if (registers(reg2, v) == false) return false;
    return set_registers(reg1, v);
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(address), imm) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    unsigned value = 0;
    if (registers(reg, value) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(address), value) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(address1), *address2) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  return true;
}

/* push imm
 * push reg
 */
bool pcvm::iPUSH(unsigned ins, unsigned mode)
{
  unsigned opcode = 0;
  unsigned offset = _registers[PCVM_REG_SP] - sizeof(unsigned);
  
  if (mode == PCVM_INS_MODE_OP_IMM) {
    unsigned imm = 0;
    if (handle_ins_mode_op_imm(ins, opcode, imm) == false)
      return false;
    
    if (invalid_offset(offset)) {
      _error = PCVM_ERROR_INVALID_ADDRESS;
      return false;
    }
    unsigned *address = nullptr;
    if (calc_address(offset, &address) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(address), imm) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG) {
    unsigned reg = 0;
    if (handle_ins_mode_op_reg(ins, opcode, reg) == false)
      return false;

    if (invalid_offset(offset)) {
      _error = PCVM_ERROR_INVALID_ADDRESS;
      return false;
    }
    unsigned *address = 0;
    if (calc_address(offset, &address) == false) return false;
    if (registers(reg, *address) == false) return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  _registers[PCVM_REG_SP] -= sizeof(unsigned);
  return true;
}

/* pop reg
 */
bool pcvm::iPOP(unsigned ins, unsigned mode)
{
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG) {
    unsigned reg = 0;
    if (handle_ins_mode_op_reg(ins, opcode, reg) == false)
      return false;
    
    unsigned offset = _registers[PCVM_REG_SP];
    if (invalid_offset(offset)) {
      _error = PCVM_ERROR_INVALID_ADDRESS;
      return false;
    }
    unsigned *address = nullptr;
    if (calc_address(offset, &address) == false) return false;
    if (set_registers(reg, *address) == false) return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  _registers[PCVM_REG_SP] += sizeof(unsigned);
  return true;
}

/* cmp reg, imm
 * cmp reg, reg
 * cmp mem, imm
 * cmp mem, reg
 * cmp mem, mem
 */
bool pcvm::iCMP(unsigned ins, unsigned mode)
{
  unsigned int v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2= 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  int res = static_cast<int>(v1) - static_cast<int>(v2);
  if (res == 0) _flags.Z = 1; else _flags.Z = 0;
  if (res < 0) _flags.C = 1; else _flags.C = 0;
  
  return true;
}

/* call imm
 * call reg
 */
bool pcvm::iCALL(unsigned ins, unsigned mode) {
  /*
   * push next instruct address
   */
  unsigned offset = _registers[PCVM_REG_SP] - sizeof(unsigned);
  if (invalid_offset(offset)) {
    _error = PCVM_ERROR_INVALID_ADDRESS;
    return false;
  }
  unsigned *address = nullptr;
  if (calc_address(offset, &address) == false) return false;
  unsigned next_address = _registers[PCVM_REG_IP];
  if (write_memory(reinterpret_cast<unsigned char*>(address), next_address) == false)
    return false;
  
  unsigned opcode = 0, jmpto = 0;
  if (mode == PCVM_INS_MODE_OP_IMM) {
    unsigned imm = 0;
    if (handle_ins_mode_op_imm(ins, opcode, imm) == false)
      return false;
    jmpto = imm;
  }
  else if (mode == PCVM_INS_MODE_OP_REG) {
    unsigned reg = 0, imm;
    if (handle_ins_mode_op_reg(ins, opcode, reg) == false)
      return false;
    if (registers(reg, imm, true) == false) return false;
    jmpto = imm & 0xFFFFF;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }

  _registers[PCVM_REG_IP] = jmpto;
  _registers[PCVM_REG_SP] = offset;
  
  return true;
}

/* ret
 */
bool pcvm::iRET(unsigned ins, unsigned mode) {
  /*
   * pop address from stack
   */
  unsigned offset = _registers[PCVM_REG_SP];
  if (invalid_offset(offset)) {
    _error = PCVM_ERROR_INVALID_ADDRESS;
    return false;
  }
  unsigned *address = nullptr;
  if (calc_address(offset, &address) == false) return false;
  _registers[PCVM_REG_IP] = *address;
  _registers[PCVM_REG_SP] = offset + sizeof(unsigned);
  
  return true;
}

/* jmp imm
 * jmp reg
 */
bool pcvm::iJMP(unsigned ins, unsigned mode)
{
  unsigned opcode = 0, address = 0;
  
  if (mode == PCVM_INS_MODE_OP_IMM) {
    unsigned imm = 0;
    if (handle_ins_mode_op_imm(ins, opcode, imm) == false)
      return false;
    address = imm;
  }
  else if (mode == PCVM_INS_MODE_OP_REG) {
    unsigned reg = 0, imm;
    if (handle_ins_mode_op_reg(ins, opcode, reg) == false)
      return false;
    if (registers(reg, imm, true) == false) return false;
    address = imm & 0xFFFFF;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  _registers[PCVM_REG_IP] = address;
  
  return true;
}

bool pcvm::iJE(unsigned ins, unsigned mode)
{
  if (_flags.Z == 0) {
    return true;
  }
  return iJMP(ins, mode);
}

bool pcvm::iJNE(unsigned ins, unsigned mode)
{
  if (_flags.Z == 1) {
    return true;
  }
  return iJMP(ins, mode);
}

bool pcvm::iJB(unsigned ins, unsigned mode)
{
  if (_flags.C == 0) {
    return true;
  }
  return iJMP(ins, mode);
}

bool pcvm::iJA(unsigned ins, unsigned mode)
{
  if (_flags.C == 1) {
    return true;
  }
  return iJMP(ins, mode);
}

bool pcvm::iJBE(unsigned ins, unsigned mode)
{
  if (_flags.Z == 1) {
    return iJMP(ins, mode);
  }
  
  return iJB(ins, mode);
}

bool pcvm::iJAE(unsigned ins, unsigned mode)
{
  if (_flags.Z == 1) {
    return iJMP(ins, mode);
  }
  
  return iJA(ins, mode);
}

/* and reg, imm
 * and reg, reg
 * and mem, imm
 * and mem, reg
 * and mem, mem
 */
bool pcvm::iAND(unsigned ins, unsigned mode)
{
  unsigned v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    v1 &= v2;
    if (set_registers(reg, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
    v1 &= v2;
    if (set_registers(reg1, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    v1 &= v2;
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
    v1 &= v2;
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
    v1 &= v2;
    if (write_memory(reinterpret_cast<unsigned char*>(address1), v1) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

/* or reg, imm
 * or reg, reg
 * or mem, imm
 * or mem, reg
 * or mem, mem
 */
bool pcvm::iOR(unsigned ins, unsigned mode)
{
  unsigned v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    v1 |= v2;
    if (set_registers(reg, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
    v1 |= v2;
    if (set_registers(reg1, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    v1 |= v2;
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
    v1 |= v2;
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
    v1 |= v2;
    if (write_memory(reinterpret_cast<unsigned char*>(address1), v1) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

/* not reg */
bool pcvm::iNOT(unsigned ins, unsigned mode)
{
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG) {
    unsigned reg = 0, value = 0;
    if (handle_ins_mode_op_reg(ins, opcode, reg) == false)
      return false;
    if (registers(reg, value) == false) return false;
    if (set_registers(reg, ~value) == false) return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  return true;
}

/* add reg, imm
 * add reg, reg
 * add mem, imm
 * add mem, reg
 * add mem, mem
 */
bool pcvm::iADD(unsigned ins, unsigned mode) {
  unsigned v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ += v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 += v2;
    }
    
    if (set_registers(reg, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ += v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 += v2;
    }
    
    if (set_registers(reg1, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ += v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 += v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ += v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 += v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ += v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 += v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address1), v1) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

bool pcvm::iSUB(unsigned ins, unsigned mode) {
  unsigned v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ -= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 -= v2;
    }
    
    if (set_registers(reg, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ -= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 -= v2;
    }
    
    if (set_registers(reg1, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ -= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 -= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ -= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 -= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ -= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 -= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address1), v1) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

bool pcvm::iMUL(unsigned ins, unsigned mode) {
  unsigned v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ *= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 *= v2;
    }
    
    if (set_registers(reg, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ *= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 *= v2;
    }
    
    if (set_registers(reg1, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ *= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 *= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ *= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 *= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ *= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 *= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address1), v1) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

bool pcvm::iDIV(unsigned ins, unsigned mode) {
  unsigned v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ /= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 /= v2;
    }
    
    if (set_registers(reg, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ /= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 /= v2;
    }
    
    if (set_registers(reg1, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ /= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 /= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ /= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 /= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ /= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 /= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address1), v1) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

bool pcvm::iMOD(unsigned ins, unsigned mode) {
  unsigned v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ %= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 %= v2;
    }
    
    if (set_registers(reg, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ %= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 %= v2;
    }
    
    if (set_registers(reg1, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ %= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 %= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ %= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 %= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
    
    if (_flags.S) {
      int v1_ = (int)v1;
      int v2_ = (int)v2;
      v1_ %= v2_;
      v1 = (unsigned)v1_;
    }
    else {
      v1 %= v2;
    }
    
    if (write_memory(reinterpret_cast<unsigned char*>(address1), v1) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

/* shl reg, imm
 * shl reg, reg
 * shl mem, imm
 * shl mem, reg
 * shl mem, mem
 */
bool pcvm::iSHL(unsigned ins, unsigned mode) {
  unsigned v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    v1 <<= v2;
    if (set_registers(reg, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
    
    v1 <<= v2;
    
    if (set_registers(reg1, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    v1 <<= v2;
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
    
    v1 <<= v2;
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
    
    v1 <<= v2;
    
    if (write_memory(reinterpret_cast<unsigned char*>(address1), v1) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

/* shr reg, imm
 * shr reg, reg
 * shr mem, imm
 * shr mem, reg
 * shr mem, mem
 */
bool pcvm::iSHR(unsigned ins, unsigned mode) {
  unsigned v1 = 0, v2 = 0;
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_REG_IMM) {
    unsigned reg = 0, imm = 0;
    if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false)
      return false;
    if (registers(reg, v1) == false) return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    v1 >>= v2;
    if (set_registers(reg, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_REG_REG) {
    unsigned reg1 = 0, reg2 = 0;
    if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false)
      return false;
    if (registers(reg1, v1) == false) return false;
    if (registers(reg2, v2) == false) return false;
    
    v1 >>= v2;
    
    if (set_registers(reg1, v1) == false) return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
    unsigned *address = nullptr, imm = 0;
    if (handle_ins_mode_op_mem_imm(ins, opcode, &address, imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), imm) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    v1 >>= v2;
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
    unsigned *address = nullptr, reg = 0;
    if (handle_ins_mode_op_mem_reg(ins, opcode, &address, reg) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address) == false)
      return false;
    if (registers(reg, v2) == false)
      return false;
    
    v1 >>= v2;
    
    if (write_memory(reinterpret_cast<unsigned char*>(address), v1) == false)
      return false;
  }
  else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
    unsigned *address1 = nullptr, *address2 = nullptr;
    if (handle_ins_mode_op_mem_mem(ins, opcode, &address1, &address2) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v1), *address1) == false)
      return false;
    if (write_memory(reinterpret_cast<unsigned char*>(&v2), *address2) == false)
      return false;
    
    v1 >>= v2;
    
    if (write_memory(reinterpret_cast<unsigned char*>(address1), v1) == false)
      return false;
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

bool pcvm::iINT(unsigned ins, unsigned mode)
{
  unsigned opcode = 0;
  if (mode == PCVM_INS_MODE_OP_IMM) {
    unsigned imm = 0;
    if (handle_ins_mode_op_imm(ins, opcode, imm) == false)
      return false;
    
    if (imm == 0) {
      unsigned port = 0, size = 0;
      if (registers(PCVM_REG_R4, port) == false) return false;
      if (port >= PCVM_IO_INPUT_NUMBER) {
        _error = PCVM_ERROR_INVALID_IO_ACCESS;
        return false;
      }
      
      if (registers(PCVM_REG_R5, size) == false) return false;
      /* fixme: check size */
      
      unsigned offset = _registers[PCVM_REG_SP];
      if (invalid_offset(offset)) {
        _error = PCVM_ERROR_INVALID_ADDRESS;
        return false;
      }
      unsigned *address = nullptr;
      if (calc_address(offset, &address) == false) return false;
      
      if (_io_input[port] == nullptr) {
        _error = PCVM_ERROR_IO_NOT_BOUNAD;
        return false;
      }
      memcpy(address, _io_input[port], size);
      
      if (set_registers(PCVM_REG_R4, size) == false) return false;
    }
    else if (imm == 1) {
      unsigned port = 0, size = 0;
      if (registers(PCVM_REG_R4, port) == false) return false;
      if (port >= PCVM_IO_INPUT_NUMBER) {
        _error = PCVM_ERROR_INVALID_IO_ACCESS;
        return false;
      }
      
      if (registers(PCVM_REG_R5, size) == false) return false;
      /* fixme: check size */
      
      unsigned offset = _registers[PCVM_REG_SP];
      if (invalid_offset(offset)) {
        _error = PCVM_ERROR_INVALID_ADDRESS;
        return false;
      }
      unsigned *address = nullptr;
      if (calc_address(offset, &address) == false) return false;
      
      if (_io_output[port] == nullptr) {
        _error = PCVM_ERROR_IO_NOT_BOUNAD;
        return false;
      }
      memcpy(_io_output[port], address, size);
      
      if (set_registers(PCVM_REG_R4, size) == false) return false;
    }
    else if (imm == 2) {
      unsigned port = 0;
      if (registers(PCVM_REG_R4, port) == false) return false;
        if (port >= PCVM_IO_INPUT_NUMBER) {
          _error = PCVM_ERROR_INVALID_INT_PARAM;
          return false;
        }
      set_registers(PCVM_REG_R5, _io_input_size[port]);
    }
    else if (imm == 3) {
      unsigned port = 0, size = 0;
      if (registers(PCVM_REG_R4, port) == false) return false;
      if (port >= PCVM_IO_OUTPUT_NUMBER) {
        _error = PCVM_ERROR_INVALID_INT_PARAM;
        return false;
      }
      if (registers(PCVM_REG_R5, size) == false) return false;
      _io_output_size[port] = size;
    }
    else if (imm == 4) {
      unsigned unit = 0;
      if (registers(PCVM_REG_R4, unit) == false) return false;
      if ((unit != 1) || (unit != 2) || (unit != 4)) {
        _error = PCVM_ERROR_INVALID_INT_PARAM;
        return false;
      }
      _flags.A = unit;
    }
    else if (imm == 5) {
      unsigned sign = 0;
      if (registers(PCVM_REG_R4, sign) == false) return false;
      _flags.S = !(sign > 0);
    }
    else if (imm == 9) {
      _shutdown = true;
    }
    else {
      _error = PCVM_ERROR_INVALID_INT_NUMBER;
      return false;
    }
  }
  else {
    _error = PCVM_ERROR_INVALID_MODE;
    return false;
  }
  
  return true;
}

bool pcvm::iNOP(unsigned ins, unsigned mode)
{
  return true;
}

#ifdef SUPPORT_DEBUGER
static std::string s_info1_fmt = "| ip  = %8x  sb  = %8x  sp  = %8x ret = %8x |     C : %u    |\n";
static std::string s_info2_fmt = "| r4  = %8x  r5  = %8x  r6  = %8x r7  = %8x |     Z : %u    |\n";
static std::string s_info3_fmt = "| r8  = %8x  r9  = %8x  r10 = %8x r11 = %8x |     S : %u    |\n";
static std::string s_info4_fmt = "| r12 = %8x  r13 = %8x  r14 = %8x r15 = %8x |     O : %u    |\n";
static std::string s_info5_fmt = "|     A : %u    |\n";

void pcvm::show_dbg_info() {
  for (int i = 0; i < 80; i++) printf("-");
  printf("\n");
  
  printf(s_info1_fmt.c_str(),
         _registers[PCVM_REG_IP],
         _registers[PCVM_REG_SB],
         _registers[PCVM_REG_SP],
         _registers[PCVM_REG_RET],
         _flags.C);
  
  printf(s_info2_fmt.c_str(),
         _registers[PCVM_REG_R4],
         _registers[PCVM_REG_R5],
         _registers[PCVM_REG_R6],
         _registers[PCVM_REG_R7],
         _flags.Z);
  
  printf(s_info3_fmt.c_str(),
         _registers[PCVM_REG_R8],
         _registers[PCVM_REG_R9],
         _registers[PCVM_REG_R10],
         _registers[PCVM_REG_R11],
         _flags.S);
  
  printf(s_info4_fmt.c_str(),
         _registers[PCVM_REG_R12],
         _registers[PCVM_REG_R13],
         _registers[PCVM_REG_R14],
         _registers[PCVM_REG_R15],
         _flags.O);
  
  printf("|");
  for (int i = 0; i < 63; i++) printf(" ");
  printf(s_info5_fmt.c_str(), _flags.A);
  
  for (int i = 0; i < 80; i++) printf("-");
  printf("\n");
}

static std::string s_reg_names[PCVM_REG_NUMBER] = {
  "ip",
  "sb",
  "sp",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15"
};

static std::string s_ins_names[PCVM_OP_NUMBER] = {
  "mov",
  "push",
  "pop",
  "cmp",
  "call",
  "ret",
  "jmp",
  "je",
  "jne",
  "jb",
  "ja",
  "jbe",
  "jae",
  "and",
  "or",
  "not",
  "add",
  "sub",
  "mul",
  "div",
  "mod",
  "shl",
  "shr",
  "int",
  "nop"
};

static std::string s_mode_fmt[PCVM_INS_MODE_NUMBER] = {
  "%s",
  "%s %x",
  "%s %s",
  "%s %s, %x",
  "%s %s, %s",
  "%s [%s], %x",
  "%s [%s], %s",
  "%s [%s], [%s]"
};

bool pcvm::disasm(unsigned ins, std::string &out) {
  unsigned opcode = 0, mode = 0;
  if (ins_2_opocde_mode(ins, opcode, mode) == false) return false;
  
  if ((opcode >= PCVM_OP_MOV) && (opcode < PCVM_OP_NUMBER)) {
    char buf[256] = { 0 };
    if (mode == PCVM_INS_MODE_OP) {
      sprintf(buf, s_mode_fmt[mode].c_str(),
              s_ins_names[opcode].c_str());
    }
    else if (mode == PCVM_INS_MODE_OP_IMM) {
      unsigned imm = 0;
      if (handle_ins_mode_op_imm(ins, opcode, imm) == false) {
        out = "decode failed";
        return false;
      }
      
      sprintf(buf, s_mode_fmt[mode].c_str(),
              s_ins_names[opcode].c_str(), imm);
    }
    else if (mode == PCVM_INS_MODE_OP_REG) {
      unsigned reg = 0;
      if (handle_ins_mode_op_reg(ins, opcode, reg) == false) {
        out = "decode failed";
        return false;
      }
      
      sprintf(buf, s_mode_fmt[mode].c_str(),
              s_ins_names[opcode].c_str(), s_reg_names[reg].c_str());
    }
    else if (mode == PCVM_INS_MODE_OP_REG_IMM) {
      unsigned reg = 0, imm = 0;
      if (handle_ins_mode_op_reg_imm(ins, opcode, reg, imm) == false) {
        out = "decode failed";
        return false;
      }
      
      sprintf(buf, s_mode_fmt[mode].c_str(),
              s_ins_names[opcode].c_str(), s_reg_names[reg].c_str(), imm);
    }
    else if (mode == PCVM_INS_MODE_OP_REG_REG) {
      unsigned reg1 = 0, reg2 = 0;
      if (handle_ins_mode_op_reg_reg(ins, opcode, reg1, reg2) == false) {
        out = "decode failed";
        return false;
      }
      
      sprintf(buf, s_mode_fmt[mode].c_str(),
              s_ins_names[opcode].c_str(), 
              s_reg_names[reg1].c_str(), 
              s_reg_names[reg2].c_str());
    }
    else if (mode == PCVM_INS_MODE_OP_MEM_IMM) {
      //unsigned address = 0, imm = 0;
      //if (handle_ins_mode_op_mem_imm(ins, opcode, address, imm) == false) {
      //	out = "decode failed";
      //	return false;
      //}
      
      pcvm_ins_mode_op_mem_imm ins_mode;
      unsigned imm = 0, reg = 0;
      if (ins_2_mode_op_mem_imm(ins, ins_mode) == false) return false;
      opcode = ins_mode.opcode;
      reg = ins_mode.reg;
      imm = ins_mode.imm;
      
      sprintf(buf, s_mode_fmt[mode].c_str(),
              s_ins_names[opcode].c_str(), s_reg_names[reg].c_str(), imm);
    }
    else if (mode == PCVM_INS_MODE_OP_MEM_REG) {
      //unsigned reg1 = 0, reg2 = 0;
      //if (handle_ins_mode_op_mem_reg(ins, opcode, reg1, reg2) == false) {
      //	out = "decode failed";
      //	return false;
      //}
      pcvm_ins_mode_op_mem_reg ins_mode;
      unsigned imm = 0, reg1 = 0, reg2 = 0;
      if (ins_2_mode_op_mem_reg(ins, ins_mode) == false) return false;
      opcode = ins_mode.opcode;
      reg1 = ins_mode.reg1;
      reg2 = ins_mode.reg2;
      
      sprintf(buf, s_mode_fmt[mode].c_str(),
              s_ins_names[opcode].c_str(), 
              s_reg_names[reg1].c_str(), 
              s_reg_names[reg2].c_str());
    }
    else if (mode == PCVM_INS_MODE_OP_MEM_MEM) {
      //unsigned reg1 = 0, reg2 = 0;
      //if (handle_ins_mode_op_mem_reg(ins, opcode, reg1, reg2) == false) {
      //	out = "decode failed";
      //	return false;
      //}
      pcvm_ins_mode_op_mem_mem ins_mode;
      unsigned imm = 0, reg1 = 0, reg2 = 0;
      if (ins_2_mode_op_mem_mem(ins, ins_mode) == false) return false;
      opcode = ins_mode.opcode;
      reg1 = ins_mode.reg1;
      reg2 = ins_mode.reg2;
      
      sprintf(buf, s_mode_fmt[mode].c_str(),
              s_ins_names[opcode].c_str(), 
              s_reg_names[reg1].c_str(), 
              s_reg_names[reg2].c_str());
    }
    else {
      out = "invalid mode";
      return false;
    }
    
    out = buf;
  }
  else {
    out = "invalid opcode";
    return false;
  }
  return true;
}

static void s_print_memory(unsigned char* datas, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if ((i != 0) && (i % 16 == 0)) {
      printf("\n");
    }
    
    printf("%02x ", datas[i]);
  }
}

static std::string s_asm_fmt = "| %4s <0x%04x> %s";
static int s_max_dis = 16;
void pcvm::debugger(unsigned curr_ip) {
  
#ifdef _MSC_VER
  system("cls");
#else
  //system("clear");
#endif
  unsigned dis_ip = (curr_ip / sizeof(unsigned) / s_max_dis) * s_max_dis * sizeof(unsigned);
  show_dbg_info();
  std::string dis = "";
  
  int i = 0;
  for (i = 0; i < s_max_dis; i++) {
    
    if (dis_ip >= _code_size) {
      break;
    }
    
    unsigned ins = *reinterpret_cast<unsigned*>(_space + dis_ip);
    if (disasm(ins, dis) == false) {
      
    }
    
    char line[80] = {0};
    if (curr_ip == dis_ip) {
      sprintf(line, s_asm_fmt.c_str(), "===>", dis_ip, dis.c_str());
    }
    else {
      sprintf(line, s_asm_fmt.c_str(), " ", dis_ip, dis.c_str());
    }
    printf(line);
    
    int line_i = 79 - strlen(line);
    for (int j = 0; j < line_i; j++) printf(" ");
    printf("|\n");
    
    dis_ip += sizeof(unsigned);
  }
  if (i < s_max_dis) goto _l1;
  i -= s_max_dis;
  while (i--) {
    printf("|");
    for (int j = 0; j < 78; j++) printf(" ");
    printf("|\n");
  }
_l1:
  for (int j = 0; j < 80; j++) printf("-");
  printf("\n");
  
  printf("pcvm> ");
_rep:
  char c = 0;
  c = fgetc(stdin);
  
  if (c == 'c') {
    return;
  }
  else if (c == 'q') {
    exit(0);
  }
  else if (c == 'd') {
  }
  else if (c == 'h') {
    printf("c continue\r\n");
    printf("q quit\r\n");
    printf("d<address>[size] dump memory(not support)\r\n");
    printf("h help\r\n");
    printf("pcvm> ");
    goto _rep;
  }
  else {
    goto _rep;
  }
}
#endif