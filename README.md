# Cheat Engine for Linux

Linux-native memory scanner, debugger, trainer, and code injection tooling inspired by Cheat Engine.

This is a from-scratch C++23/Qt6 implementation. It uses native Linux APIs such as `process_vm_readv`, `ptrace`, `/proc`, explicit Vulkan layers, and an optional privileged kernel helper instead of Wine or Windows compatibility layers.

Current local source snapshot: about 21.9K lines across 113 C/C++ source/header files, excluding `build/`.

## Status

Most planned user-facing CE-style features are implemented:

- Memory scanning: numeric/string/AOB/binary/all-types/grouped/custom Lua formula scans
- Next scans: changed/unchanged/increased/decreased/same-as-first/percentage comparisons
- Memory editing: typed reads/writes, freeze modes, address list records, hotkeys
- Tables/trainers: CE-style `.CT` XML, protected `.CETRAINER`, standalone trainer generation
- Debugging: hardware/software breakpoints, conditions, one-shot/thread filters, break-and-trace, exception breakpoints
- Auto-assembler: allocation, labels, symbols, AOB scans, data directives, `readmem`, `reassemble`, `loadbinary`, `loadlibrary`, `createthread`, `{$try}/{$except}`
- Lua 5.3 compatibility surface for memory, scans, table/address-list state, utility dialogs, hotkeys, threads, debug metadata, and Qt GUI objects
- Analysis: code references, function/call graph discovery, code caves, RIP-relative scans, structures, stack traces
- Remote/network: ceserver TCP handshake client, GDB remote client, network compression, distributed pointer scan sharding
- Overlay: X11 click-through overlay and a Vulkan explicit layer injection path
- Managed runtimes: Mono/CoreCLR detection, managed object enumeration, type extraction, JIT-address method breakpoint bridge
- Optional kernel helper: privileged process memory access, physical memory access, virtual-to-physical address translation, kernel symbol lookup

One planned item remains intentionally unimplemented: kernel process hiding. This project does not include rootkit-style stealth behavior. Prefer explicit filtering inside this tool's own UI for legitimate workflow cleanup.

## Build

### Dependencies

Ubuntu/Debian baseline:

```bash
sudo apt install build-essential cmake qt6-base-dev libcapstone-dev zlib1g-dev linux-headers-$(uname -r)
```

Keystone is usually built from source:

```bash
git clone --depth 1 https://github.com/keystone-engine/keystone.git /tmp/keystone
cmake -S /tmp/keystone -B /tmp/keystone/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD=X86
cmake --build /tmp/keystone/build -j$(nproc)
sudo cmake --install /tmp/keystone/build
sudo ldconfig
```

Lua 5.3 is expected from the adjacent Cheat Engine source tree:

```bash
cd "../Cheat Engine/lua53/lua53"
make linux MYCFLAGS="-fPIC"
cd ../../../cecore
```

### Compile

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Optional kernel helper:

```bash
make -C /lib/modules/$(uname -r)/build M=$PWD/kernel modules
sudo insmod kernel/cecore_kmod.ko
sudo rmmod cecore_kmod
make -C /lib/modules/$(uname -r)/build M=$PWD/kernel clean
```

## Run

```bash
# GUI
sudo LD_LIBRARY_PATH=build build/cheatengine

# CLI
sudo LD_LIBRARY_PATH=build build/cescan --help

# Speedhack example
CE_SPEED=2.0 LD_PRELOAD=build/libspeedhack.so ./game
```

## Validation

The current regression pass used during development is:

```bash
cmake --build build -j$(nproc)
./build/cecore_test
./build/cescan --help
git diff --check
make -C /lib/modules/$(uname -r)/build M=$PWD/kernel modules
make -C /lib/modules/$(uname -r)/build M=$PWD/kernel clean
```

Known warning: Qt may emit `QMenu::addAction` deprecation warnings during GUI builds.

## CLI Reference

```text
cescan list                          List all processes
cescan scan <pid> [options]          Scan process memory
cescan read <pid> <addr> [size]      Hex dump memory
cescan write <pid> <addr> <val>      Write a typed value
cescan disasm <pid> <addr> [count]   Disassemble instructions
cescan modules <pid>                 List loaded modules
cescan regions <pid>                 List memory regions
```

Common scan options include:

```text
--type byte|i16|i32|i64|pointer|float|double|string|unicode|aob|binary|all|grouped|custom
--value <value>
--value2 <value>
--compare exact|greater|less|between|changed|unchanged|increased|decreased|unknown|samefirst
--encoding <iconv-name>
--rounding exact|rounded|truncated|extreme
--percent <pct>
--percent2 <pct>
--previous <result-dir>
--writable
```

## Auto-Assembler Example

```asm
[ENABLE]
alloc(newmem, 1024)
label(returnhere)

newmem:
  {$try}
  assert(game+1234, 48 89 45 10)
  mov dword [rax+10], 999
  {$except}
  nop 5
  {$endtry}
  jmp returnhere

game+1234:
  jmp newmem
  returnhere:

[DISABLE]
game+1234:
  db 48 89 45 10 90
dealloc(newmem)
```

## Architecture

```text
cecore/
├── analysis/       code analysis, managed runtime helpers, structures
├── arch/           Capstone disassembler and Keystone assembler wrappers
├── cli/            cescan command-line tool
├── core/           types, auto-assembler, expressions, tables, trainers
├── debug/          breakpoint manager, debug session, tracing, GDB remote
├── gui/            Qt6 application windows and overlay
├── kernel/         optional cecore_kmod privileged helper
├── packaging/      desktop/AppImage helpers
├── platform/       network compression, Vulkan layer helpers
├── platform/linux/ process API, ptrace, injector, ceserver, kernel client
├── plugins/        plugin loader and speedhack
├── scanner/        memory scanner and pointer scanner
├── scripting/      Lua engine and bindings
├── symbols/        ELF and kernel symbol resolvers
└── test/           regression harness
```

## Kernel Helper Scope

`kernel/cecore_kmod.c` is optional. It exposes explicit, CAP_SYS_ADMIN-gated ioctls through `/dev/cecore` for:

- target process memory read/write
- physical-address read/write via page-sized `ioremap` windows
- virtual-to-physical translation for a target process page

It does not hide processes, modules, files, sockets, or kernel objects.

## Vulkan Overlay Scope

The build produces `libce_vulkan_overlay_layer.so`, an explicit Vulkan loader layer. The cecore helper API can generate the JSON manifest and launch environment for `VK_LAYER_CE_linux_overlay`. The current layer is an injection/dispatch foundation; the X11 overlay window provides the visible OSD/crosshair path.

## License

Inspired by [Cheat Engine](https://github.com/cheat-engine/cheat-engine) by Dark Byte. Check upstream licensing before distributing derived assets or compatibility data.
