module main

import shellcode
import os
import cli { Command, Flag }

const (
  default_offs = '0x0'
  default_addr = '0x0'
)

fn main() {
  mut app := &Command {
    name: 'vscl',
    description: 'Portable shellcode launcher\n
Example:  vscl -i examples/macos_sh_x64.bin -a 0x10ca65000 -I :0xcafebabe ^eax\n
Extra Args:
  ^reg${" ".repeat(16)}Insert xor reg, reg
  :imm16, :imm32${" ".repeat(6)}Insert push immediate',
    usage: '(:imm16/imm32) (^reg)',
    disable_man: true,
    disable_help: true,
    commands: [],
    flags: [
      Flag {
        flag: .string,
        name: 'input',
        abbrev: 'i',
        description: 'Input binary file',
        required: true
      },
      Flag {
        flag: .string,
        name: 'offset',
        abbrev: 'o',
        description: 'Offset where to start the execution',
        default_value: [ default_offs ]
      },
      Flag {
        flag: .string,
        name: 'addr',
        abbrev: 'a',
        description: 'Base address to inject the shellcode (0 would let mmap choose the address)',
        default_value: [ default_addr ]
      },
      Flag {
        flag: .bool,
        name: 'ret',
        abbrev: 'R',
        description: 'Add a return (ret) at shellcode end'
        default_value: [ 'false' ]
      },
      Flag {
        flag: .bool,
        name: 'int',
        abbrev: 'I',
        description: 'Add interrupt (int3) at shellcode start'
        default_value: [ 'false' ]
      },
      Flag {
        flag: .bool,
        name: 'nofork',
        abbrev: 'nf',
        description: 'Don\'t fork before running the shellcode'
        default_value: [ 'false' ]
      },
      Flag {
        flag: .bool,
        name: 'out',
        abbrev: 'c',
        description: 'Output the shellcode in a C style array and exit'
        default_value: [ 'false' ]
      },
    ],
    execute: do
  }

  if os.args.len < 3 || '-h' in os.args || '-help' in os.args {
    eprint(app.help_message())
    exit(1)
  }

  app.setup()
  app.parse(os.args)
}

fn do(cmd Command) ! {
  $if windows {
    return error('Windows not implemented yet')
  }

  mut flags := cmd.flags.clone()

  filepath := flags.get_string('input')!
  if !os.exists(filepath) || !os.is_readable(filepath) {
    return error("Input file does not exists or can't be read")
  }

  mut sc := shellcode.Shellcode{
    @return: flags.get_bool('ret')!,
    interrupt: flags.get_bool('int')!,
    offset: flags.get_string('offset')!.u32()
    addr: flags.get_string('addr')!.u64()
  }

  if cmd.args.len > 0 {
    for arg in cmd.args {
      if arg.len < 3 {
        println(cmd.help_message())
        return
      }
      match arg[0] {
        `:` { sc.push << arg[1..] }
        `^` { sc.clear << arg[1..] }
        else {
          return error('Argument `$arg` not recognized.')
        }
      }
    }
  }

  sc.load(filepath) or { return err }
  defer {
    sc.unload() or { println(err) }
  }

  if flags.get_bool('out')! {
    sc.print(0, true)
    return
  }

  if !flags.get_bool('nofork')! {
    pid := os.fork()
    if pid == 0 {
      sc.exec()
    }
    $if debug {
      println('Child process id: $pid')
    }
    os.wait()
  } else { sc.exec() }
}
