# Cheat Engine for Linux

<p align="center">
  <strong>A Linux-native memory scanner, debugger, and code injection tool</strong><br>
  Rewritten from scratch in C++23 with Qt6 — no Wine, no compatibility layers
</p>

---

## What is this?

This is a from-scratch reimplementation of [Cheat Engine](https://cheatengine.org/) for Linux. Instead of porting the original 400K-line Pascal codebase, we rewrote the core engine in modern C++ using native Linux APIs (`process_vm_readv`, `ptrace`, `/proc` filesystem).

**9,120 lines of C++** replacing 400,000 lines of Pascal.

## Features

### Memory Scanning
- Multi-threaded scanner (uses all CPU cores)
- Value types: byte, int16, int32, int64, float, double, string, array of bytes, binary, "all types"
- Grouped scans (`vtGrouped`) and Lua formula scans (`soCustom`)
- AOB scanning with `??` wildcards
- Scan comparisons: exact, greater, less, between, changed, unchanged, increased, decreased, unknown
- Handles processes with 1GB+ of memory in under a second

### Memory Editing
- Read/write any value type to process memory
- Freeze values with directional modes (normal, increase only, decrease only, never increase, never decrease)
- Address list with groups, descriptions, and editable values
- Save/load cheat tables in CE-compatible `.CT` XML format

### Disassembler & Assembler
- **Capstone** x86-64 disassembler with ELF symbol resolution (`libc.so!printf`)
- **Keystone** x86-64 assembler (NASM syntax)
- Memory browser with hex view + disassembly, dark themed

### Auto-Assembler
CE-compatible script engine:
```
[ENABLE]
alloc(newmem, 1024)
label(returnhere)

newmem:
  mov dword [rax+10], 999
  jmp returnhere

game+1234:
  jmp newmem
  returnhere:

[DISABLE]
game+1234:
  db 48 89 45 10 90
dealloc(newmem)
```

Supports: `alloc`, `dealloc`, `label`, `define`, `registersymbol`, `aobscan`, `aobscanmodule`, `assert`, `fullaccess`, `createthread`, `include`, `reassemble`, `readmem`, `loadbinary`, `db`/`dw`/`dd`/`dq`, `[ENABLE]`/`[DISABLE]` sections.

### Pointer Scanner
Find stable pointer chains to dynamic addresses:
```
$ sudo cescan pointerscan <pid> 0x7f1234 4 2048
Found 130 pointer paths:
  [game+4048]+0x20  -> 0x7f1234
  [[libc.so.6+202e20]+0x10]+0x20  -> 0x7f1234
```

### Debugger
- Hardware breakpoints (DR0-DR3) for execute, read, write, access
- **"Find what accesses this address"** — logs all instructions reading an address
- **"Find what writes to this address"** — logs all instructions modifying an address
- **Break and trace** — single-step N instructions, log each with full register state
- Conditional breakpoints (Lua expressions)
- Breakpoint list manager

### Lua 5.3 Scripting
55+ CE-compatible functions:
```lua
-- Read/write memory
local health = readInteger(0x7f1234)
writeInteger(0x7f1234, 999)

-- Create custom GUI
local f = createForm()
f.Caption = "My Trainer"
local btn = createButton(f)
btn.Caption = "Infinite Health"
btn.OnClick = function() writeInteger(healthAddr, 999) end
f:show()

-- Scan memory
local ms = createMemScan()
ms:firstScan(soExactValue, vtDword, "100")
print("Found: " .. ms:getFoundCount())

-- Grouped/custom scans
ms:firstScan(soExactValue, vtGrouped, "i32:1337@0;float:2.5@4;byte:66@8")
ms:firstScan(soCustom, vtDword,
  "local b1,b2,b3,b4=string.byte(current,1,4); return b1==0xCD and b2==0xAB and b3==0x34 and b4==0x12")
```

### Code Analysis
- Module dissection (find all calls, jumps, string references)
- Code cave scanner (find unused regions for injection)
- Referenced strings/functions enumeration

### Additional Features
- **.so injection** via ptrace + dlopen
- **Speedhack** — LD_PRELOAD library intercepting `clock_gettime`/`nanosleep`
- **Trainer generator** — compile standalone C trainers from cheat tables
- **Plugin system** — load `.so` plugins via dlopen
- **Structure dissector** — view memory as struct fields with auto-detection
- **Dark theme** (Catppuccin Mocha)

## Build

### Dependencies

```bash
# Ubuntu/Debian
sudo apt install build-essential cmake qt6-base-dev libcapstone-dev libreadline-dev

# Keystone assembler (not in apt — build from source)
git clone --depth 1 https://github.com/keystone-engine/keystone.git /tmp/keystone
cd /tmp/keystone && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="X86" ..
make -j$(nproc) && sudo make install && sudo ldconfig
```

### Compile

```bash
# Build Lua 5.3
cd "Cheat Engine/lua53/lua53" && make linux MYCFLAGS="-fPIC" && cd ../../..

# Build cecore
cd cecore
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Run

```bash
# GUI (needs root for process_vm_readv)
sudo LD_LIBRARY_PATH=build build/cheatengine

# CLI
sudo LD_LIBRARY_PATH=build build/cescan --help

# Speedhack (2x speed)
CE_SPEED=2.0 LD_PRELOAD=build/libspeedhack.so ./game
```

## CLI Reference

```
cescan list                              List all processes
cescan scan <pid> --type i32 --value 100 First scan for int32 = 100
cescan scan <pid> --type grouped --value "i32:100@0;float:1.5@4" Grouped scan
cescan scan <pid> --type custom --value-size 4 --value "local b1,b2,b3,b4=string.byte(current,1,4); return b1==0xCD and b2==0xAB and b3==0x34 and b4==0x12" Custom Lua formula scan
cescan scan <pid> --type aob --value "7F 45 ?? 46"  AOB scan with wildcards
cescan read <pid> <addr> [size]          Hex dump memory
cescan write <pid> <addr> <val> --type i32  Write value
cescan disasm <pid> <addr> [count]       Disassemble with symbols
cescan symbols <pid>                     List ELF symbols
cescan modules <pid>                     List loaded modules
cescan regions <pid>                     List memory regions
cescan pointerscan <pid> <addr> [depth]  Find pointer chains
cescan asm <pid> script.cea              Run auto-assembler script
```

## Architecture

```
cecore/ (9,120 lines, 72 files)
├── core/           types, auto-assembler, expression parser, cheat tables, trainer
├── platform/linux/ process_vm_readv, ptrace, .so injection
├── arch/           Capstone disassembler, Keystone assembler
├── scanner/        multi-threaded memory scanner, pointer scanner
├── symbols/        ELF symbol resolver
├── debug/          breakpoint manager, code finder, tracer
├── analysis/       code dissection, code caves
├── scripting/      Lua 5.3 engine + CE API + Qt GUI bindings
├── plugins/        .so plugin loader, speedhack
├── gui/            Qt6 (15 windows, dark theme)
├── cli/            cescan command-line tool
└── packaging/      AppImage, .desktop
```

## Tech Stack

- **C++23** (GCC 13+)
- **Qt6** (GUI)
- **CMake** (build system)
- **Capstone** (disassembly)
- **Keystone** (assembly)
- **Lua 5.3** (scripting)
- **Linux APIs**: `process_vm_readv`/`writev`, `ptrace`, `/proc` filesystem

## vs Original Cheat Engine

| | Original CE | This Project |
|---|---|---|
| Language | Pascal (400K lines) | C++23 (9K lines) |
| Platform | Windows (Wine on Linux) | Native Linux |
| GUI | LCL/GTK2 | Qt6 |
| Kernel driver | Windows DBK32 | ptrace + /proc (no driver needed) |
| Memory access | ReadProcessMemory API | process_vm_readv (faster) |
| Disassembler | Hand-coded (29K lines) | Capstone (500 lines wrapper) |
| Assembler | Hand-coded (10K lines) | Keystone (90 lines wrapper) |

## License

Based on [Cheat Engine](https://github.com/cheat-engine/cheat-engine) by Dark Byte.
