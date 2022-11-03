module shellcode

struct Instruction {
mut:
  opcode    u8
  size      int   = 1
  prefix    u8
  operands  []u8  = []u8{}
}

const (
  int3 =  Instruction{ opcode: u8(0xCC) }
  xor  =  Instruction{ opcode: u8(0x31) }
  ret  =  Instruction{ opcode: u8(0xC3) }
  push =  Instruction{ opcode: u8(0x68) }
)

// return an array containing the instruction's bytes
fn (ins Instruction) get() &u8 {
  unsafe {
    mut pos := 0
    mut bytes := malloc(ins.size)
    if ins.prefix != 0 {
      bytes[pos] = ins.prefix
      pos++
    }
    bytes[pos] = ins.opcode
    pos++

    if ins.size > 1 {
      for i := 0; pos < ins.size; pos++, i++ {
        bytes[pos] = ins.operands[i]
      }
    }
    return bytes
  }
}

// construct instructions depending on bits, register and exra operands
// NOTE: this function does not take care of endianness
fn (mut inst Instruction) set(what string, extra []u8) ? {
  mut len := extra.len
  if !what.starts_with('imm') {
    len++
  }
  inst.operands = []u8{len:len}

  mut pos := 1
  match what {
    'imm16'  {
        inst.size = 4
        inst.prefix = 0x66
        pos-- }
    'ax'  {
        inst.size = 3
        inst.prefix = 0x66
        inst.operands[0] = 0xc0 }
    'bx'  {
        inst.size = 3
        inst.prefix = 0x66
        inst.operands[0] = 0xdb }
    'cx'  {
        inst.size = 3
        inst.prefix = 0x66
        inst.operands[0] = 0xc9 }
    'dx'  {
        inst.size = 3
        inst.prefix = 0x66
        inst.operands[0] = 0xd2 }
    'imm32' {
        inst.size = 5
        pos-- }
    'eax' {
        inst.size = 2
        inst.operands[0] = 0xc0 }
    'ebx' {
        inst.size = 2
        inst.operands[0] = 0xdb }
    'ecx' {
        inst.size = 2
        inst.operands[0] = 0xc9 }
    'edx' {
        inst.size = 2
        inst.operands[0] = 0xd2 }
    'ebp' {
        inst.size = 2
        inst.operands[0] = 0xed }
    'esp' {
        inst.size = 2
        inst.operands[0] = 0xe4 }
    'esi' {
        inst.size = 2
        inst.operands[0] = 0xf6 }
    'edi' {
        inst.size = 2
        inst.operands[0] = 0xff }
    'rax' {
        inst.size = 3
        inst.prefix = 0x48
        inst.operands[0] = 0xc0 }
    'rbx' {
        inst.size = 3
        inst.prefix = 0x48
        inst.operands[0] = 0xdb }
    'rcx' {
        inst.size = 3
        inst.prefix = 0x48
        inst.operands[0] = 0xc9 }
    'rdx' {
        inst.size = 3
        inst.prefix = 0x48
        inst.operands[0] = 0xd2 }
    'rbp' {
        inst.size = 3
        inst.prefix = 0x48
        inst.operands[0] = 0xed }
    'rsp' {
        inst.size = 3
        inst.prefix = 0x48
        inst.operands[0] = 0xe4 }
    'rsi' {
        inst.size = 3
        inst.prefix = 0x48
        inst.operands[0] = 0xf6 }
    'rdi' {
        inst.size = 3
        inst.prefix = 0x48
        inst.operands[0] = 0xff }
    'r8'  {
        inst.size = 3
        inst.prefix = 0x4d
        inst.operands[0] = 0xc0 }
    'r9'  {
        inst.size = 3
        inst.prefix = 0x4d
        inst.operands[0] = 0xc9 }
    'r10' {
        inst.size = 3
        inst.prefix = 0x4d
        inst.operands[0] = 0xd2 }
    'r11' {
        inst.size = 3
        inst.prefix = 0x4d
        inst.operands[0] = 0xdb }
    'r12' {
        inst.size = 3
        inst.prefix = 0x4d
        inst.operands[0] = 0xe4 }
    'r13' {
        inst.size = 3
        inst.prefix = 0x4d
        inst.operands[0] = 0xed }
    'r14' {
        inst.size = 3
        inst.prefix = 0x4d
        inst.operands[0] = 0xf6 }
    'r15' {
        inst.size = 3
        inst.prefix = 0x4d
        inst.operands[0] = 0xff }
    else { return error('Instruction unknown or unsupported. Check asm.v for supported registers and actions.') }
  }

  if extra.len > 0 {
    for b in extra {
      inst.operands[pos] = b
      pos++
    }
  }
}

