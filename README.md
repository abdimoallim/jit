### jit

A header-only, cross-platform JIT compiler library in C. Targets x86-32, x86-64, ARM32 and ARM64.

### Features

- Targets x86-32, x86-64, ARM32, ARM64, RISC-V 64 (auto-detected or set `JIT_ARCH`)
- Works on Windows, Linux, macOS and any POSIX system
- Works with any C89+ compiler (GCC, Clang, MSVC, TCC, etc)
- Full instruction set: arithmetic, logic, shifts, memory, branches, calls, stack frames
- Label + fixup system for forward/backward jumps and loops
- Buffer auto-grow which starts small and doubles on overflow
- Zero external dependencies, only requires libc

### Usage

```c
#include "jit.h"

typedef long long (*fn2)(long long, long long);

int main(void) {
  jit_buf j;
  jit_init(&j, 0);           // 0 → use default capacity (4096 bytes)

  jit_prolog(&j);            // push rbp; mov rbp, rsp
  jit_mov_rr64(&j, RAX, RDI);
  jit_add_rr64(&j, RAX, RSI);
  jit_epilog(&j);            // mov rsp, rbp; pop rbp; ret

  fn2 add = (fn2)jit_compile(&j);
  printf("%lld\n", add(3, 5));  // 8

  jit_free(&j);
}
```

Compile and run (after including [`jit.h`](/jit.h)):

```sh
gcc -O2 -o prog prog.c && ./prog
```

### API

#### Lifecycle

| Function           | Description                                            |
| ------------------ | ------------------------------------------------------ |
| `jit_init(j, cap)` | Allocate RWX buffer. `cap=0` → 4096 bytes              |
| `jit_free(j)`      | Free buffer                                            |
| `jit_compile(j)`   | Patch all labels, flush icache, return `void*` to code |
| `jit_fn(j)`        | Return raw pointer without patching                    |

#### Labels & branches

Labels emit forward/backward jumps without knowing the target address up front.

```c
int lbl_loop = jit_label(&j);  // allocate label id
int lbl_end  = jit_label(&j);

jit_bind(&j, lbl_loop);        // mark current position as lbl_loop

jit_cmp_ri64(&j, RCX, 0);
jit_jcc_lbl(&j, JIT_CC_EQ, lbl_end);  // jump to lbl_end if RCX == 0

// ... loop body ...
jit_jmp_lbl(&j, lbl_loop);

jit_bind(&j, lbl_end);
```

All fixups are resolved when you call `jit_compile()`.

#### Condition codes (`jit_cc`)

| Code         | Meaning                   |
| ------------ | ------------------------- |
| `JIT_CC_EQ`  | Equal / zero              |
| `JIT_CC_NE`  | Not equal                 |
| `JIT_CC_LT`  | Signed less than          |
| `JIT_CC_LE`  | Signed less or equal      |
| `JIT_CC_GT`  | Signed greater than       |
| `JIT_CC_GE`  | Signed greater or equal   |
| `JIT_CC_ULT` | Unsigned less than        |
| `JIT_CC_ULE` | Unsigned less or equal    |
| `JIT_CC_UGT` | Unsigned greater than     |
| `JIT_CC_UGE` | Unsigned greater or equal |

Used by: `jit_jcc_lbl`, `jit_setcc`, `jit_cmov_rr64`.

### x86-64 Instruction Reference

#### Register enum

```
RAX RCX RDX RBX RSP RBP RSI RDI R8–R15
EAX ECX EDX EBX ESP EBP ESI EDI
```

#### Stack frames

```c
jit_prolog(j)                // push rbp; mov rbp, rsp
jit_epilog(j)                // mov rsp, rbp; pop rbp; ret
jit_prolog_frame(j, n)       // prolog + sub rsp, n (aligned to 16)
jit_epilog_frame(j)          // same as epilog
```

#### Move

```c
jit_mov_rr64(j, dst, src)          // dst = src  (64-bit)
jit_mov_rr32(j, dst, src)          // dst = src  (32-bit)
jit_mov_ri64(j, dst, imm64)        // dst = imm64
jit_mov_ri32(j, dst, imm32)        // dst = imm32 (zero extends)
jit_mov_rm64(j, dst, base, disp)   // dst = [base+disp]
jit_mov_mr64(j, base, disp, src)   // [base+disp] = src
jit_mov_rm32(j, dst, base, disp)
jit_mov_mr32(j, base, disp, src)
jit_mov_mr8 (j, base, disp, src)
jit_movzx_rm8 (j, dst, base, disp) // zero-extend byte  → 64-bit
jit_movzx_rm16(j, dst, base, disp) // zero-extend word  → 64-bit
jit_movsx_r32_r8(j, dst, src)      // sign-extend byte  → 32-bit
jit_movsx_r64_r32(j, dst, src)     // sign-extend dword → 64-bit
jit_movzx_r32_r8(j, dst, src)
jit_movzx_r64_r32(j, dst, src)
jit_lea_rm(j, dst, base, disp)     // dst = base+disp (LEA)
```

#### Arithmetic

```c
jit_add_rr64(j, dst, src)
jit_add_ri64(j, dst, imm32)
jit_add_rr32(j, dst, src)
jit_add_ri32(j, dst, imm32)
jit_add_rm64(j, dst, base, disp)   // dst += [base+disp]
jit_sub_rr64(j, dst, src)
jit_sub_ri64(j, dst, imm32)
jit_sub_rr32(j, dst, src)
jit_sub_ri32(j, dst, imm32)
jit_imul_rr64(j, dst, src)         // dst *= src (signed)
jit_imul_rr32(j, dst, src)
jit_neg_r64(j, r)                  // r = -r
jit_neg_r32(j, r)
jit_idiv_r64(j, src)               // RDX:RAX / src → RAX (quot), RDX (rem)
jit_idiv_r32(j, src)               // use jit_cqo / jit_cdq first
jit_div_r64(j, src)                // unsigned
jit_div_r32(j, src)
jit_cqo(j)                         // sign-extend RAX → RDX:RAX
jit_cdq(j)                         // sign-extend EAX → EDX:EAX
```

#### Logic

```c
jit_and_rr64(j, dst, src)   jit_and_ri64(j, dst, imm32)
jit_or_rr64(j, dst, src)    jit_or_ri64(j, dst, imm32)
jit_xor_rr64(j, dst, src)   jit_xor_ri64(j, dst, imm32)
jit_not_r64(j, r)
jit_and_rr32 / jit_or_rr32 / jit_xor_rr32 / jit_not_r32  (same pattern)
```

#### Shifts

```c
jit_shl_ri64(j, dst, src, shift)   // dst = src << shift
jit_shr_ri64(j, dst, src, shift)   // dst = src >> shift  (logical)
jit_sar_ri64(j, dst, src, shift)   // dst = src >> shift  (arithmetic)
jit_shl_rr64(j, r)   // shift r left  by CL
jit_shr_rr64(j, r)   // shift r right by CL (logical)
jit_sar_rr64(j, r)   // shift r right by CL (arithmetic)
// _32 variants exist for all of the above
```

#### Compare & conditional

```c
jit_cmp_rr64(j, a, b)
jit_cmp_ri64(j, a, imm32)
jit_cmp_rr32(j, a, b)
jit_cmp_ri32(j, a, imm32)
jit_test_rr64(j, a, b)        // sets flags on a & b, discards result
jit_test_rr32(j, a, b)
jit_setcc(j, cc, dst)         // dst = (condition ? 1 : 0) — 8-bit
jit_cmov_rr64(j, cc, dst, src) // if (cc) dst = src  (no branch)
jit_cmov_rr32(j, cc, dst, src)
```

#### Jumps & calls

```c
jit_jmp_lbl(j, lbl)           // unconditional jump to label
jit_jmp_r64(j, r)             // jmp *r
jit_jmp_rel32(j, rel)         // jmp rel32
jit_jcc_lbl(j, cc, lbl)       // conditional jump to label
jit_call_abs(j, ptr)          // call absolute address (via RAX)
jit_call_r64(j, r)            // call *r
jit_call_rel32(j, rel)        // call rel32
jit_ret(j)                    // ret
```

#### Stack

```c
jit_push_r64(j, r)
jit_pop_r64(j, r)
jit_sub_rsp(j, n)             // sub rsp, n
jit_add_rsp(j, n)             // add rsp, n
jit_xchg_rr64(j, a, b)
```

#### Bit operations

```c
jit_bswap_r64(j, r)
jit_bswap_r32(j, r)
jit_popcnt_r64(j, dst, src)
jit_popcnt_r32(j, dst, src)
jit_lzcnt_r32(j, dst, src)
jit_tzcnt_r32(j, dst, src)
```

#### Misc

```c
jit_nop(j)
```

### x86-32 details

Same patterns as x86-64 but without `REX` prefixes and only 8 registers (`EAX`–`EDI`). The `_64` suffix functions are not available. Calling convention on Linux is `cdecl` (args on stack), on Windows `stdcall` or `cdecl` depending on target.

### ARM64 details

Instructions use a 3-operand form: `jit_add_rr64(j, dst, a, b)`. Registers are `X0`–`X30`, `XZR`/`SP`. `jit_prolog` saves `FP`/`LR` and sets up the frame pointer. Call external functions with `jit_bl_abs(j, tmp_reg, fn_ptr)`.

### ARM32 details

Same 3-operand form. Registers `R0`–`R15` with aliases `SP=13`, `LR=14`, `PC=15`. `jit_prolog` saves `FP`/`LR` via `PUSH`. Call externals with `jit_bl_abs(j, tmp_reg, fn_ptr)`.

### RISC-V 64 details

RV64GC (base integer + M extension for mul/div). Instructions use a 3-operand form: `jit_add_rr64(j, dst, a, b)`.

#### Register enum

```
ZERO  RA    SP    GP    TP
T0–T2       (temporaries)
S0/FP S1    (saved / frame pointer)
A0–A7       (args / return values: A0=return)
S2–S11      (saved)
T3–T6       (temporaries)
```

#### Arithmetic & logic

```c
jit_add_rr64(j, d, a, b)     jit_add_ri64(j, d, s, imm12)
jit_sub_rr64(j, d, a, b)
jit_mul_rr64(j, d, a, b)
jit_div_rr64(j, d, a, b)     // signed (requires M ext)
jit_divu_rr64(j, d, a, b)    // unsigned
jit_rem_rr64(j, d, a, b)     // signed remainder
jit_remu_rr64(j, d, a, b)    // unsigned remainder
jit_neg_r64(j, d, s)
jit_not_r64(j, d, s)
jit_and_rr64(j, d, a, b)     jit_and_ri64(j, d, s, imm12)
jit_or_rr64(j, d, a, b)      jit_or_ri64(j, d, s, imm12)
jit_xor_rr64(j, d, a, b)     jit_xor_ri64(j, d, s, imm12)
jit_shl_ri64(j, d, s, sh)    jit_shl_rr64(j, d, a, b)
jit_shr_ri64(j, d, s, sh)    jit_shr_rr64(j, d, a, b)   // logical
jit_sar_ri64(j, d, s, sh)    jit_sar_rr64(j, d, a, b)   // arithmetic
```

#### Word (32-bit) ops

```c
jit_add_rr32(j, d, a, b)     // ADDW - sign-extends to 64-bit
jit_sub_rr32(j, d, a, b)     // SUBW
jit_mul_rr32(j, d, a, b)     // MULW
jit_div_rr32(j, d, a, b)     // DIVW
jit_rem_rr32(j, d, a, b)     // REMW
jit_shl_ri32(j, d, s, sh)    // SLLIW
jit_shr_ri32(j, d, s, sh)    // SRLIW
jit_sar_ri32(j, d, s, sh)    // SRAIW
```

#### Memory

```c
jit_ld64(j, dst, base, off)    // LD  — load 64-bit
jit_ld32(j, dst, base, off)    // LW  — sign-extend
jit_ld32u(j, dst, base, off)   // LWU — zero-extend
jit_ld16(j, dst, base, off)    // LH
jit_ld16u(j, dst, base, off)   // LHU
jit_ld8(j, dst, base, off)     // LB
jit_ld8u(j, dst, base, off)    // LBU
jit_sd64(j, src, base, off)    // SD
jit_sd32(j, src, base, off)    // SW
jit_sd16(j, src, base, off)    // SH
jit_sd8(j, src, base, off)     // SB
```

#### Compare & set

```c
jit_slt_rr(j, d, a, b)          // d = (a < b) signed
jit_sltu_rr(j, d, a, b)         // d = (a < b) unsigned
jit_slt_ri(j, d, s, imm12)
jit_sltu_ri(j, d, s, imm12)
jit_seqz(j, d, s)               // d = (s == 0)
jit_snez(j, d, s)               // d = (s != 0)
jit_sltz(j, d, s)               // d = (s < 0)
jit_sgtz(j, d, s)               // d = (s > 0)
```

#### Branches

On RV64, `jit_jcc_lbl` takes **two source registers** to compare directly (no prior `cmp`):

```c
jit_jcc_lbl(j, cc, rs1, rs2, lbl)
```

```c
jit_jcc_lbl(&j, JIT_CC_EQ, A0, A1, lbl)  // branch if A0 == A1
jit_jcc_lbl(&j, JIT_CC_LT, A0, ZERO, lbl) // branch if A0 < 0
jit_jmp_lbl(&j, lbl)
jit_jmp_r64(&j, r)                         // jalr zero, 0(r)
jit_call_abs(&j, T0, fn_ptr)               // load address into T0, jalr ra, 0(T0)
```

#### Stack & frames

```c
jit_prolog(j)            // addi sp,-16; sd ra,8(sp); sd fp,0(sp); addi fp,sp,16
jit_epilog(j)            // ld ra,8(sp); ld fp,0(sp); addi sp,16; ret
jit_prolog_frame(j, n)   // same but allocates n extra bytes (16-byte aligned)
jit_epilog_frame(j)      // same as epilog
```

## Building & testing

```sh
# native x86-64
make test

# RISC-V 64 via QEMU (requires riscv64-linux-gnu-gcc and qemu-riscv64)
make test-rv64

# all targets
make
```

Install the RV64 toolchain on Debian/Ubuntu:

```sh
sudo apt install gcc-riscv64-linux-gnu qemu-user-static
```

Then:

```sh
# x86-64 native
gcc -O2 -o test.x86-64 test.x86-64.c && ./test.x86-64

# RISC-V 64 (requires riscv64-linux-gnu-gcc + qemu-riscv64)
riscv64-linux-gnu-gcc -O2 -static -o test.rv64 test.rv64.c
qemu-riscv64 ./test.rv64
```

If QEMU can't find the libc for the binary, you may also need `libc6-riscv64-cross`, but the `-static` flag should make that a non-issue.

`JIT_ARCH` is auto-detected from compiler predefined macros. Override it manually if cross-compiling:

```c
#define JIT_ARCH JIT_ARCH_ARM64
#include "jit.h"
```

Available values: `JIT_ARCH_X86_32`, `JIT_ARCH_X86_64`, `JIT_ARCH_ARM32`, `JIT_ARCH_ARM64`, `JIT_ARCH_RV64`.

The [x86-64](/test.x86-64.c) test suite covers: constants, arithmetic (add/sub/mul/div), bitwise ops, shifts, negation, sign extension, branches, loops, stack frames, local variables, C function calls, conditional moves, setcc, LEA, bswap, popcnt, buffer grow, factorial, fibonacci and multi-label dispatch.

The [RV64](/test.rv64.c) suite covers: constants (including large 48-bit), all ALU ops (add/sub/mul/div/rem), bitwise, shifts (imm/reg), slt/sltu, branches (eq/ne/lt/le/gt/ge), loops, stack locals, memory load/store, immediate arithmetic, C function calls, multi-label dispatch, W (32-bit) ops and buffer grow.

### Examples

#### Loop: sum 0..n

```c
jit_buf j;
jit_init(&j, 0);
jit_prolog(&j);
jit_mov_ri64(&j, RAX, 0);    // acc = 0
jit_mov_ri64(&j, RCX, 0);    // i   = 0
int lbl_loop = jit_label(&j);
int lbl_end  = jit_label(&j);
jit_bind(&j, lbl_loop);
jit_cmp_rr64(&j, RCX, RDI);  // cmp i, n
jit_jcc_lbl(&j, JIT_CC_GE, lbl_end);
jit_add_rr64(&j, RAX, RCX);  // acc += i
jit_add_ri64(&j, RCX, 1);    // i++
jit_jmp_lbl(&j, lbl_loop);
jit_bind(&j, lbl_end);
jit_epilog(&j);
long long (*sum)(long long) = jit_compile(&j);
printf("%lld\n", sum(10));    // 45
```

#### Conditional: max(a, b)

```c
jit_buf j;
jit_init(&j, 0);
jit_prolog(&j);
jit_mov_rr64(&j, RAX, RDI);
jit_cmp_rr64(&j, RDI, RSI);
jit_cmov_rr64(&j, JIT_CC_LT, RAX, RSI);   // if a < b: RAX = b
jit_epilog(&j);
long long (*maxfn)(long long,long long) = jit_compile(&j);
printf("%lld\n", maxfn(3, 7));  // 7
```

#### Stack frame with local variable

```c
jit_buf j;
jit_init(&j, 0);
jit_prolog_frame(&j, 16);     // allocate 16 bytes on stack
jit_mov_mr64(&j, RBP, -8, RDI);   // [rbp-8] = arg0
jit_mov_rm64(&j, RAX, RBP, -8);   // RAX = [rbp-8]
jit_add_ri64(&j, RAX, 1);
jit_epilog_frame(&j);
long long (*inc)(long long) = jit_compile(&j);
printf("%lld\n", inc(41));     // 42
```

#### Calling a C function from JIT code

```c
jit_buf j;
jit_init(&j, 0);
jit_prolog_frame(&j, 0);
jit_sub_rsp(&j, 8);               // align stack to 16 bytes before call
jit_mov_ri64(&j, RDI, (long long)(uintptr_t)"hello\n");
jit_call_abs(&j, (void*)puts);
jit_add_rsp(&j, 8);
jit_mov_ri64(&j, RAX, 0);
jit_epilog_frame(&j);
((void(*)(void))jit_compile(&j))();
```

### License

Apache v2.0 License
