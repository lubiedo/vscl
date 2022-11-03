module shellcode

import os
import term { bold,red,green }

#include "sys/mman.h"

fn C.mmap(addr voidptr, length int, prot int, flags int, fd int, offset u64) &u8
fn C.munmap(addr voidptr, length int) int

pub struct Shellcode {
  fork      bool
  interrupt bool
  @return   bool
  offset    u32
  addr      u64
mut:
  body      &u8 = &[]u8{}
  size      u64
pub mut:
  clear     []string
  push      []string
}

// load shellcode binary into memory
pub fn (mut sc Shellcode) load(path string) ? {
  sc.size = os.file_size(path)
  if sc.size == 0 {
    return error('Unable to get file size')
  }
  $if debug {
    println('Loading $path (size: $sc.size)')
  }

  mut insert := []Instruction{}
  if sc.interrupt {
    sc.size += u64(int3.size)
    insert << int3
  }
  if sc.@return {
    sc.size += u64(ret.size)
  }

  for reg in sc.clear {
    mut inst := xor
    inst.set(reg, []) or { return err }
    insert << inst
    sc.size += u64(inst.size)
  }

  for pushes in sc.push {
    imm := imm_to_array(pushes.u32()) or { return err }
    mut inst := push
    inst.set(if imm.len == 2 { 'imm16' } else { 'imm32' }, imm) or
      { return err }
    insert << inst
    sc.size += u64(inst.size)
  }

  mut mapping := C.MAP_PRIVATE | C.MAP_ANONYMOUS
  if sc.addr != 0 {
    mapping |= C.MAP_FIXED
  }

  sc.body = C.mmap(sc.addr, sc.size,
                    C.PROT_READ | C.PROT_WRITE | C.PROT_EXEC,
                    mapping,
                    -1, 0)

  if sc.body == voidptr(-1) {
    return error('Error while mapping memory')
  }

  mut pos := 0
  for inst in insert {
    sc.insert_inst(inst, u32(pos))
    pos += inst.size
  }

  data := os.read_file(path)?
  unsafe {
    buf := data.bytes()

    mut i := pos
    mut j := 0
    for j < data.len {
      sc.body[i] = buf[j]
      i++, j++
    }
  }

  pos += data.len
  if sc.@return {
    sc.insert_inst(ret, u32(pos))
  }
  $if debug {
    println('Shellcode mapped at: 0x${sc.body:X} (length: $sc.size)')
  }
}

// run shellcode
pub fn (sc Shellcode) exec() {

  // $if debug {
    sc.print(sc.offset, false)
  // }

  ptr := sc.body
  $if x64 {
    asm amd64 {
      add rax, off
      call rax
      ;
      ; r(ptr)
        r(u64(sc.offset)) as off
    }
  } $else {
    asm i386 {
      add eax, off
      call eax
      ;
      ; r(ptr)
        r(sc.offset) as off
    }
  }

  $if debug {
    println('Done shellcode execution')
  }
}

// unload shellcode from memory map
pub fn (mut sc Shellcode) unload() ? {
  err := C.munmap(sc.body, sc.size)
  if err == -1 {
    return error('Error unloading memory mapping ($ret)')
  }
  $if debug {
    println('Shellcode unmapped')
  }
}

// print shellcode body in hexadecimal format with coloring or c array
pub fn (sc &Shellcode) print(offset u32, c_style bool) {
  mut out := '\n'
  unsafe {
    if c_style {
      out += 'unsigned char shellcode[] = {\n  '
      for i in 0 .. sc.size {
        out += '0x${sc.body[i]:02x}'
        out += if i+1 < sc.size { ', ' } else { '\n' }
        if (i+1) % 8 == 0  && i+1 < sc.size {
          out += '\n  '
        }
      }
      out += '};\n'
      out += 'unsigned int shelcode = $sc.size;\n'
    } else {
      for i in 0 .. sc.size {
          s := '${sc.body[i]:02X} '
          if s == '00 ' {
            out += bold(red(s))
          } else {
            out += if offset == i { green(s) } else { s }
          }
        if (i+1) % 8 == 0 {
          out += ' '.repeat(4)
        }
        if (i+1) % 16 == 0  || i+1 == sc.size {
          out += '\n'
        }
      }
    }
    println(out)
  }
}

// insert instruction opcode at the start of the shellcode 
fn (mut sc Shellcode) insert_inst(inst Instruction, offset u32) {
  unsafe {
    bytes := inst.get()
    for i in 0 .. inst.size {
      sc.body[offset + i] = bytes[i]
    }
  }
}

// convert unsigned int to an array of its bytes
fn imm_to_array(n u32) ?[]u8 {
  mut result := []u8{len:4}
  result[3] = u8(n & 0xff)
  result[2] = u8(n >> 8 & 0xff)
  result[1] = u8(n >> 16 & 0xff)
  result[0] = u8(n >> 24 & 0xff)

  if n >> 16 > 0 { return result }
  else if n >> 8 > 0 {
    mut result2 := []u8{len:2}
    result2[0] = result[2]
    result2[1] = result[3]
    return result2
  } else {
    //return []u8{len:1, init:result[3]}
    return error('Use of imm8 not implemented')
  }
}

