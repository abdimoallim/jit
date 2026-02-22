#ifndef JIT_H
#define JIT_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define JIT_ARCH_X86_32 1
#define JIT_ARCH_X86_64 2
#define JIT_ARCH_ARM32 3
#define JIT_ARCH_ARM64 4

#if !defined(JIT_ARCH)
#if defined(__x86_64__) || defined(_M_X64)
#define JIT_ARCH JIT_ARCH_X86_64
#elif defined(__i386__) || defined(_M_IX86)
#define JIT_ARCH JIT_ARCH_X86_32
#elif defined(__aarch64__) || defined(_M_ARM64)
#define JIT_ARCH JIT_ARCH_ARM64
#elif defined(__arm__) || defined(_M_ARM)
#define JIT_ARCH JIT_ARCH_ARM32
#else
#error "Unsupported architecture"
#endif
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef size_t usz;

#define JIT_MAX_REGS 32
#define JIT_MAX_FIXUPS 256
#define JIT_MAX_LABELS 256
#define JIT_INIT_CAP 4096

typedef enum {
  JIT_TYPE_I8 = 0,
  JIT_TYPE_I16,
  JIT_TYPE_I32,
  JIT_TYPE_I64,
  JIT_TYPE_F32,
  JIT_TYPE_F64,
  JIT_TYPE_PTR
} jit_type;

typedef enum {
  JIT_CC_EQ = 0,
  JIT_CC_NE,
  JIT_CC_LT,
  JIT_CC_LE,
  JIT_CC_GT,
  JIT_CC_GE,
  JIT_CC_ULT,
  JIT_CC_ULE,
  JIT_CC_UGT,
  JIT_CC_UGE
} jit_cc;

typedef struct {
  u8* buf;
  usz len;
  usz cap;
  int arch;
  usz labels[JIT_MAX_LABELS];
  int nlabels;

  struct {
    usz off;
    int lbl;
    int sz;
  } fixups[JIT_MAX_FIXUPS];

  int nfixups;
} jit_buf;

static int jit_init(jit_buf* j, usz cap) {
  if (!cap)
    cap = JIT_INIT_CAP;
#if defined(_WIN32)
  j->buf = (u8*)VirtualAlloc(NULL, cap, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
  if (!j->buf)
    return -1;
#else
  j->buf = (u8*)mmap(NULL, cap, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (j->buf == MAP_FAILED) {
    j->buf = NULL;
    return -1;
  }
#endif
  j->len = 0;
  j->cap = cap;
  j->arch = JIT_ARCH;
  j->nlabels = 0;
  j->nfixups = 0;
  return 0;
}

static void jit_free(jit_buf* j) {
  if (!j->buf)
    return;
#if defined(_WIN32)
  VirtualFree(j->buf, 0, MEM_RELEASE);
#else
  munmap(j->buf, j->cap);
#endif
  j->buf = NULL;
}

static void jit_flush(jit_buf* j) {
#if defined(__arm__) || defined(__aarch64__)
  __builtin___clear_cache((char*)j->buf, (char*)(j->buf + j->len));
#elif defined(_WIN32)
  FlushInstructionCache(GetCurrentProcess(), j->buf, j->len);
#else
  (void)j;
#endif
}

static void* jit_fn(jit_buf* j) {
  return (void*)j->buf;
}

static void jit_ensure(jit_buf* j, usz n) {
  if (j->len + n <= j->cap)
    return;
  usz nc = j->cap * 2 + n;
#if defined(_WIN32)
  u8* nb = (u8*)VirtualAlloc(NULL, nc, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
  if (nb) {
    memcpy(nb, j->buf, j->len);
    VirtualFree(j->buf, 0, MEM_RELEASE);
    j->buf = nb;
    j->cap = nc;
  }
#else
  u8* nb = (u8*)mmap(NULL, nc, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (nb != MAP_FAILED) {
    memcpy(nb, j->buf, j->len);
    munmap(j->buf, j->cap);
    j->buf = nb;
    j->cap = nc;
  }
#endif
}

static void jit_emit1(jit_buf* j, u8 b) {
  jit_ensure(j, 1);
  j->buf[j->len++] = b;
}

static void jit_emit2(jit_buf* j, u8 a, u8 b) {
  jit_emit1(j, a);
  jit_emit1(j, b);
}

static void jit_emit3(jit_buf* j, u8 a, u8 b, u8 c) {
  jit_emit1(j, a);
  jit_emit1(j, b);
  jit_emit1(j, c);
}

static void jit_emit4(jit_buf* j, u8 a, u8 b, u8 c, u8 d) {
  jit_emit1(j, a);
  jit_emit1(j, b);
  jit_emit1(j, c);
  jit_emit1(j, d);
}

static void jit_emit_i32(jit_buf* j, i32 v) {
  jit_ensure(j, 4);
  j->buf[j->len + 0] = (u8)(v);
  j->buf[j->len + 1] = (u8)(v >> 8);
  j->buf[j->len + 2] = (u8)(v >> 16);
  j->buf[j->len + 3] = (u8)(v >> 24);
  j->len += 4;
}

static void jit_emit_i64(jit_buf* j, i64 v) {
  jit_ensure(j, 8);
  j->buf[j->len + 0] = (u8)(v);
  j->buf[j->len + 1] = (u8)(v >> 8);
  j->buf[j->len + 2] = (u8)(v >> 16);
  j->buf[j->len + 3] = (u8)(v >> 24);
  j->buf[j->len + 4] = (u8)(v >> 32);
  j->buf[j->len + 5] = (u8)(v >> 40);
  j->buf[j->len + 6] = (u8)(v >> 48);
  j->buf[j->len + 7] = (u8)(v >> 56);
  j->len += 8;
}

static int jit_label(jit_buf* j) {
  int id = j->nlabels++;
  j->labels[id] = (usz)-1;
  return id;
}

static void jit_bind(jit_buf* j, int lbl) {
  j->labels[lbl] = j->len;
}

static void jit_patch(jit_buf* j) {
  int i;
  for (i = 0; i < j->nfixups; i++) {
    usz off = j->fixups[i].off;
    int lbl = j->fixups[i].lbl;
    int sz = j->fixups[i].sz;
    usz tgt = j->labels[lbl];
    if (tgt == (usz)-1)
      continue;
    if (sz == 4) {
      i32 rel = (i32)(tgt - (off + 4));
      j->buf[off + 0] = (u8)(rel);
      j->buf[off + 1] = (u8)(rel >> 8);
      j->buf[off + 2] = (u8)(rel >> 16);
      j->buf[off + 3] = (u8)(rel >> 24);
    } else if (sz == 1) {
      i8 rel = (i8)(tgt - (off + 1));
      j->buf[off] = (u8)rel;
    }
  }
  j->nfixups = 0;
}

static void jit_add_fixup(jit_buf* j, usz off, int lbl, int sz) {
  if (j->nfixups < JIT_MAX_FIXUPS) {
    j->fixups[j->nfixups].off = off;
    j->fixups[j->nfixups].lbl = lbl;
    j->fixups[j->nfixups].sz = sz;
    j->nfixups++;
  }
}

#if JIT_ARCH == JIT_ARCH_X86_64 || JIT_ARCH == JIT_ARCH_X86_32

typedef enum {
  RAX = 0,
  RCX = 1,
  RDX = 2,
  RBX = 3,
  RSP = 4,
  RBP = 5,
  RSI = 6,
  RDI = 7,
  R8 = 8,
  R9 = 9,
  R10 = 10,
  R11 = 11,
  R12 = 12,
  R13 = 13,
  R14 = 14,
  R15 = 15,
  EAX = 0,
  ECX = 1,
  EDX = 2,
  EBX = 3,
  ESP = 4,
  EBP = 5,
  ESI = 6,
  EDI = 7
} jit_reg;

#if JIT_ARCH == JIT_ARCH_X86_64
#define X64_REX_W 0x48
#define X64_REX_WR 0x4C
#define X64_REX_WB 0x49
#define X64_REX_WRB 0x4D

static void x64_rex(jit_buf* j, int w, int r, int x, int b) {
  u8 rex = 0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0);
  if (rex != 0x40 || w)
    jit_emit1(j, rex);
}

static void x64_modrm(jit_buf* j, int mod, int reg, int rm) {
  jit_emit1(j, (u8)((mod << 6) | ((reg & 7) << 3) | (rm & 7)));
}

static void x64_sib(jit_buf* j, int sc, int idx, int base) {
  jit_emit1(j, (u8)((sc << 6) | ((idx & 7) << 3) | (base & 7)));
}

static void jit_x64_reg_rex(jit_buf* j, int w, int dst, int src) {
  x64_rex(j, w, (dst >> 3) & 1, 0, (src >> 3) & 1);
}

static void jit_mov_rr64(jit_buf* j, int dst, int src) {
  jit_x64_reg_rex(j, 1, dst, src);
  jit_emit1(j, 0x8B);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_mov_rr32(jit_buf* j, int dst, int src) {
  jit_x64_reg_rex(j, 0, dst, src);
  jit_emit1(j, 0x8B);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_mov_ri64(jit_buf* j, int dst, i64 imm) {
  x64_rex(j, 1, 0, 0, (dst >> 3) & 1);
  jit_emit1(j, (u8)(0xB8 | (dst & 7)));
  jit_emit_i64(j, imm);
}

static void jit_mov_ri32(jit_buf* j, int dst, i32 imm) {
  if (dst >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, (u8)(0xB8 | (dst & 7)));
  jit_emit_i32(j, imm);
}

static void jit_mov_rm64(jit_buf* j, int dst, int base, i32 disp) {
  jit_x64_reg_rex(j, 1, dst, base);
  jit_emit1(j, 0x8B);
  if (disp == 0 && (base & 7) != RBP) {
    x64_modrm(j, 0, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
  } else if (disp >= -128 && disp <= 127) {
    x64_modrm(j, 1, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x64_modrm(j, 2, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit_i32(j, disp);
  }
}

static void jit_mov_mr64(jit_buf* j, int base, i32 disp, int src) {
  jit_x64_reg_rex(j, 1, src, base);
  jit_emit1(j, 0x89);
  if (disp == 0 && (base & 7) != RBP) {
    x64_modrm(j, 0, src & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
  } else if (disp >= -128 && disp <= 127) {
    x64_modrm(j, 1, src & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x64_modrm(j, 2, src & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit_i32(j, disp);
  }
}

static void jit_mov_rm32(jit_buf* j, int dst, int base, i32 disp) {
  jit_x64_reg_rex(j, 0, dst, base);
  jit_emit1(j, 0x8B);
  if (disp == 0 && (base & 7) != RBP) {
    x64_modrm(j, 0, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
  } else if (disp >= -128 && disp <= 127) {
    x64_modrm(j, 1, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x64_modrm(j, 2, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit_i32(j, disp);
  }
}

static void jit_mov_mr32(jit_buf* j, int base, i32 disp, int src) {
  jit_x64_reg_rex(j, 0, src, base);
  jit_emit1(j, 0x89);
  if (disp == 0 && (base & 7) != RBP) {
    x64_modrm(j, 0, src & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
  } else if (disp >= -128 && disp <= 127) {
    x64_modrm(j, 1, src & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x64_modrm(j, 2, src & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit_i32(j, disp);
  }
}

static void jit_add_rm64(jit_buf* j, int dst, int base, i32 disp) {
  jit_x64_reg_rex(j, 1, dst, base);
  jit_emit1(j, 0x03);
  if (disp == 0 && (base & 7) != RBP) {
    x64_modrm(j, 0, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
  } else if (disp >= -128 && disp <= 127) {
    x64_modrm(j, 1, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x64_modrm(j, 2, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit_i32(j, disp);
  }
}

static void jit_movzx_rm8(jit_buf* j, int dst, int base, i32 disp) {
  jit_x64_reg_rex(j, 1, dst, base);
  jit_emit2(j, 0x0F, 0xB6);
  if (disp == 0 && (base & 7) != RBP) {
    x64_modrm(j, 0, dst & 7, base & 7);
  } else if (disp >= -128 && disp <= 127) {
    x64_modrm(j, 1, dst & 7, base & 7);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x64_modrm(j, 2, dst & 7, base & 7);
    jit_emit_i32(j, disp);
  }
}

static void jit_movzx_rm16(jit_buf* j, int dst, int base, i32 disp) {
  jit_x64_reg_rex(j, 1, dst, base);
  jit_emit2(j, 0x0F, 0xB7);
  if (disp == 0 && (base & 7) != RBP) {
    x64_modrm(j, 0, dst & 7, base & 7);
  } else if (disp >= -128 && disp <= 127) {
    x64_modrm(j, 1, dst & 7, base & 7);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x64_modrm(j, 2, dst & 7, base & 7);
    jit_emit_i32(j, disp);
  }
}

static void jit_mov_mr8(jit_buf* j, int base, i32 disp, int src) {
  if (src >= 4)
    x64_rex(j, 0, (src >> 3) & 1, 0, (base >> 3) & 1);
  jit_emit1(j, 0x88);
  if (disp == 0 && (base & 7) != RBP) {
    x64_modrm(j, 0, src & 7, base & 7);
  } else if (disp >= -128 && disp <= 127) {
    x64_modrm(j, 1, src & 7, base & 7);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x64_modrm(j, 2, src & 7, base & 7);
    jit_emit_i32(j, disp);
  }
}

#define X64_ALU2(name, op8, op32_rm, op32_mr, /***/ ext)                       \
  static void jit_##name##_rr32(jit_buf* j, int dst, int src) {                \
    jit_x64_reg_rex(j, 0, dst, src);                                           \
    jit_emit1(j, op32_rm);                                                     \
    x64_modrm(j, 3, dst & 7, src & 7);                                         \
  }                                                                            \
  static void jit_##name##_rr64(jit_buf* j, int dst, int src) {                \
    jit_x64_reg_rex(j, 1, dst, src);                                           \
    jit_emit1(j, op32_rm);                                                     \
    x64_modrm(j, 3, dst & 7, src & 7);                                         \
  }                                                                            \
  static void jit_##name##_ri32(jit_buf* j, int dst, i32 imm) {                \
    jit_x64_reg_rex(j, 0, 0, dst);                                             \
    jit_emit1(j, 0x81);                                                        \
    x64_modrm(j, 3, ext, dst & 7);                                             \
    jit_emit_i32(j, imm);                                                      \
  }                                                                            \
  static void jit_##name##_ri64(jit_buf* j, int dst, i32 imm) {                \
    jit_x64_reg_rex(j, 1, 0, dst);                                             \
    jit_emit1(j, 0x81);                                                        \
    x64_modrm(j, 3, ext, dst & 7);                                             \
    jit_emit_i32(j, imm);                                                      \
  }

X64_ALU2(add, 0x00, 0x03, 0x01, 0)
X64_ALU2(sub, 0x28, 0x2B, 0x29, 5)
X64_ALU2(and, 0x20, 0x23, 0x21, 4)
X64_ALU2(or, 0x08, 0x0B, 0x09, 1)
X64_ALU2(xor, 0x30, 0x33, 0x31, 6)

#undef X64_ALU2

static void jit_imul_rr32(jit_buf* j, int dst, int src) {
  jit_x64_reg_rex(j, 0, dst, src);
  jit_emit2(j, 0x0F, 0xAF);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_imul_rr64(jit_buf* j, int dst, int src) {
  jit_x64_reg_rex(j, 1, dst, src);
  jit_emit2(j, 0x0F, 0xAF);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_idiv_r32(jit_buf* j, int src) {
  if (src >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xF7);
  x64_modrm(j, 3, 7, src & 7);
}

static void jit_idiv_r64(jit_buf* j, int src) {
  x64_rex(j, 1, 0, 0, (src >> 3) & 1);
  jit_emit1(j, 0xF7);
  x64_modrm(j, 3, 7, src & 7);
}

static void jit_div_r32(jit_buf* j, int src) {
  if (src >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xF7);
  x64_modrm(j, 3, 6, src & 7);
}

static void jit_div_r64(jit_buf* j, int src) {
  x64_rex(j, 1, 0, 0, (src >> 3) & 1);
  jit_emit1(j, 0xF7);
  x64_modrm(j, 3, 6, src & 7);
}

static void jit_neg_r32(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xF7);
  x64_modrm(j, 3, 3, r & 7);
}

static void jit_neg_r64(jit_buf* j, int r) {
  x64_rex(j, 1, 0, 0, (r >> 3) & 1);
  jit_emit1(j, 0xF7);
  x64_modrm(j, 3, 3, r & 7);
}

static void jit_not_r32(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xF7);
  x64_modrm(j, 3, 2, r & 7);
}

static void jit_not_r64(jit_buf* j, int r) {
  x64_rex(j, 1, 0, 0, (r >> 3) & 1);
  jit_emit1(j, 0xF7);
  x64_modrm(j, 3, 2, r & 7);
}

static void jit_shl_ri32(jit_buf* j, int dst, int src, u8 sh) {
  if (dst != src)
    jit_mov_rr32(j, dst, src);
  if (dst >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xC1);
  x64_modrm(j, 3, 4, dst & 7);
  jit_emit1(j, sh);
}

static void jit_shr_ri32(jit_buf* j, int dst, int src, u8 sh) {
  if (dst != src)
    jit_mov_rr32(j, dst, src);
  if (dst >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xC1);
  x64_modrm(j, 3, 5, dst & 7);
  jit_emit1(j, sh);
}

static void jit_sar_ri32(jit_buf* j, int dst, int src, u8 sh) {
  if (dst != src)
    jit_mov_rr32(j, dst, src);
  if (dst >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xC1);
  x64_modrm(j, 3, 7, dst & 7);
  jit_emit1(j, sh);
}

static void jit_shl_ri64(jit_buf* j, int dst, int src, u8 sh) {
  if (dst != src)
    jit_mov_rr64(j, dst, src);
  x64_rex(j, 1, 0, 0, (dst >> 3) & 1);
  jit_emit1(j, 0xC1);
  x64_modrm(j, 3, 4, dst & 7);
  jit_emit1(j, sh);
}

static void jit_shr_ri64(jit_buf* j, int dst, int src, u8 sh) {
  if (dst != src)
    jit_mov_rr64(j, dst, src);
  x64_rex(j, 1, 0, 0, (dst >> 3) & 1);
  jit_emit1(j, 0xC1);
  x64_modrm(j, 3, 5, dst & 7);
  jit_emit1(j, sh);
}

static void jit_sar_ri64(jit_buf* j, int dst, int src, u8 sh) {
  if (dst != src)
    jit_mov_rr64(j, dst, src);
  x64_rex(j, 1, 0, 0, (dst >> 3) & 1);
  jit_emit1(j, 0xC1);
  x64_modrm(j, 3, 7, dst & 7);
  jit_emit1(j, sh);
}

static void jit_shl_rr32(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xD3);
  x64_modrm(j, 3, 4, r & 7);
}

static void jit_shr_rr32(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xD3);
  x64_modrm(j, 3, 5, r & 7);
}

static void jit_sar_rr32(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xD3);
  x64_modrm(j, 3, 7, r & 7);
}

static void jit_shl_rr64(jit_buf* j, int r) {
  x64_rex(j, 1, 0, 0, (r >> 3) & 1);
  jit_emit1(j, 0xD3);
  x64_modrm(j, 3, 4, r & 7);
}

static void jit_shr_rr64(jit_buf* j, int r) {
  x64_rex(j, 1, 0, 0, (r >> 3) & 1);
  jit_emit1(j, 0xD3);
  x64_modrm(j, 3, 5, r & 7);
}

static void jit_sar_rr64(jit_buf* j, int r) {
  x64_rex(j, 1, 0, 0, (r >> 3) & 1);
  jit_emit1(j, 0xD3);
  x64_modrm(j, 3, 7, r & 7);
}

static void jit_cmp_rr32(jit_buf* j, int a, int b) {
  jit_x64_reg_rex(j, 0, a, b);
  jit_emit1(j, 0x3B);
  x64_modrm(j, 3, a & 7, b & 7);
}

static void jit_cmp_rr64(jit_buf* j, int a, int b) {
  jit_x64_reg_rex(j, 1, a, b);
  jit_emit1(j, 0x3B);
  x64_modrm(j, 3, a & 7, b & 7);
}

static void jit_cmp_ri32(jit_buf* j, int a, i32 imm) {
  if (a >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0x81);
  x64_modrm(j, 3, 7, a & 7);
  jit_emit_i32(j, imm);
}

static void jit_cmp_ri64(jit_buf* j, int a, i32 imm) {
  x64_rex(j, 1, 0, 0, (a >> 3) & 1);
  jit_emit1(j, 0x81);
  x64_modrm(j, 3, 7, a & 7);
  jit_emit_i32(j, imm);
}

static void jit_test_rr32(jit_buf* j, int a, int b) {
  jit_x64_reg_rex(j, 0, b, a);
  jit_emit1(j, 0x85);
  x64_modrm(j, 3, b & 7, a & 7);
}

static void jit_test_rr64(jit_buf* j, int a, int b) {
  jit_x64_reg_rex(j, 1, b, a);
  jit_emit1(j, 0x85);
  x64_modrm(j, 3, b & 7, a & 7);
}

static void jit_setcc(jit_buf* j, jit_cc cc, int dst) {
  static const u8 setcc_ops[] = {0x94, 0x95, 0x9C, 0x9E, 0x9F,
                                 0x9D, 0x92, 0x96, 0x97, 0x93};
  if (dst >= 8)
    x64_rex(j, 0, 0, 0, 1);
  else
    x64_rex(j, 0, 0, 0, 0);
  jit_emit2(j, 0x0F, setcc_ops[cc]);
  x64_modrm(j, 3, 0, dst & 7);
}

static void jit_movsx_r32_r8(jit_buf* j, int dst, int src) {
  jit_x64_reg_rex(j, 0, dst, src);
  jit_emit2(j, 0x0F, 0xBE);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_movsx_r64_r32(jit_buf* j, int dst, int src) {
  jit_x64_reg_rex(j, 1, dst, src);
  jit_emit1(j, 0x63);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_movzx_r32_r8(jit_buf* j, int dst, int src) {
  jit_x64_reg_rex(j, 0, dst, src);
  jit_emit2(j, 0x0F, 0xB6);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_movzx_r64_r32(jit_buf* j, int dst, int src) {
  jit_x64_reg_rex(j, 0, dst, src);
  jit_emit1(j, 0x8B);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_jmp_rel32(jit_buf* j, i32 rel) {
  jit_emit1(j, 0xE9);
  jit_emit_i32(j, rel);
}

static void jit_jmp_lbl(jit_buf* j, int lbl) {
  jit_emit1(j, 0xE9);
  jit_add_fixup(j, j->len, lbl, 4);
  jit_emit_i32(j, 0);
}

static void jit_jmp_r64(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xFF);
  x64_modrm(j, 3, 4, r & 7);
}

static void jit_jcc_lbl(jit_buf* j, jit_cc cc, int lbl) {
  static const u8 jcc_ops[] = {0x84, 0x85, 0x8C, 0x8E, 0x8F,
                               0x8D, 0x82, 0x86, 0x87, 0x83};
  jit_emit2(j, 0x0F, jcc_ops[cc]);
  jit_add_fixup(j, j->len, lbl, 4);
  jit_emit_i32(j, 0);
}

static void jit_call_rel32(jit_buf* j, i32 rel) {
  jit_emit1(j, 0xE8);
  jit_emit_i32(j, rel);
}

static void jit_call_r64(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, 0xFF);
  x64_modrm(j, 3, 2, r & 7);
}

static void jit_call_abs(jit_buf* j, void* fn) {
  jit_mov_ri64(j, RAX, (i64)(uintptr_t)fn);
  jit_call_r64(j, RAX);
}

static void jit_push_r64(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, (u8)(0x50 | (r & 7)));
}

static void jit_pop_r64(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit1(j, (u8)(0x58 | (r & 7)));
}

static void jit_ret(jit_buf* j) {
  jit_emit1(j, 0xC3);
}

static void jit_nop(jit_buf* j) {
  jit_emit1(j, 0x90);
}

static void jit_cdq(jit_buf* j) {
  jit_emit1(j, 0x99);
}

static void jit_cqo(jit_buf* j) {
  jit_emit2(j, 0x48, 0x99);
}

static void jit_add_rsp(jit_buf* j, i32 n) {
  x64_rex(j, 1, 0, 0, 0);
  jit_emit1(j, 0x81);
  x64_modrm(j, 3, 0, RSP);
  jit_emit_i32(j, n);
}

static void jit_sub_rsp(jit_buf* j, i32 n) {
  x64_rex(j, 1, 0, 0, 0);
  jit_emit1(j, 0x81);
  x64_modrm(j, 3, 5, RSP);
  jit_emit_i32(j, n);
}

static void jit_lea_rm(jit_buf* j, int dst, int base, i32 disp) {
  jit_x64_reg_rex(j, 1, dst, base);
  jit_emit1(j, 0x8D);
  if (disp == 0 && (base & 7) != RBP) {
    x64_modrm(j, 0, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
  } else if (disp >= -128 && disp <= 127) {
    x64_modrm(j, 1, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x64_modrm(j, 2, dst & 7, base & 7);
    if ((base & 7) == RSP)
      x64_sib(j, 0, RSP, RSP);
    jit_emit_i32(j, disp);
  }
}

static void jit_xchg_rr64(jit_buf* j, int a, int b) {
  jit_x64_reg_rex(j, 1, a, b);
  jit_emit1(j, 0x87);
  x64_modrm(j, 3, a & 7, b & 7);
}

static void jit_cmov_rr32(jit_buf* j, jit_cc cc, int dst, int src) {
  static const u8 cmov_ops[] = {0x44, 0x45, 0x4C, 0x4E, 0x4F,
                                0x4D, 0x42, 0x46, 0x47, 0x43};
  jit_x64_reg_rex(j, 0, dst, src);
  jit_emit2(j, 0x0F, cmov_ops[cc]);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_cmov_rr64(jit_buf* j, jit_cc cc, int dst, int src) {
  static const u8 cmov_ops[] = {0x44, 0x45, 0x4C, 0x4E, 0x4F,
                                0x4D, 0x42, 0x46, 0x47, 0x43};
  jit_x64_reg_rex(j, 1, dst, src);
  jit_emit2(j, 0x0F, cmov_ops[cc]);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_bswap_r32(jit_buf* j, int r) {
  if (r >= 8)
    x64_rex(j, 0, 0, 0, 1);
  jit_emit2(j, 0x0F, (u8)(0xC8 | (r & 7)));
}

static void jit_bswap_r64(jit_buf* j, int r) {
  x64_rex(j, 1, 0, 0, (r >> 3) & 1);
  jit_emit2(j, 0x0F, (u8)(0xC8 | (r & 7)));
}

static void jit_popcnt_r32(jit_buf* j, int dst, int src) {
  jit_emit1(j, 0xF3);
  jit_x64_reg_rex(j, 0, dst, src);
  jit_emit2(j, 0x0F, 0xB8);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_popcnt_r64(jit_buf* j, int dst, int src) {
  jit_emit1(j, 0xF3);
  jit_x64_reg_rex(j, 1, dst, src);
  jit_emit2(j, 0x0F, 0xB8);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_lzcnt_r32(jit_buf* j, int dst, int src) {
  jit_emit1(j, 0xF3);
  jit_x64_reg_rex(j, 0, dst, src);
  jit_emit2(j, 0x0F, 0xBD);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_tzcnt_r32(jit_buf* j, int dst, int src) {
  jit_emit1(j, 0xF3);
  jit_x64_reg_rex(j, 0, dst, src);
  jit_emit2(j, 0x0F, 0xBC);
  x64_modrm(j, 3, dst & 7, src & 7);
}

static void jit_prolog_x64(jit_buf* j) {
  jit_push_r64(j, RBP);
  jit_mov_rr64(j, RBP, RSP);
}

static void jit_epilog_x64(jit_buf* j) {
  jit_mov_rr64(j, RSP, RBP);
  jit_pop_r64(j, RBP);
  jit_ret(j);
}

static void jit_prolog_frame(jit_buf* j, i32 frame_sz) {
  jit_push_r64(j, RBP);
  jit_mov_rr64(j, RBP, RSP);
  if (frame_sz > 0) {
    if (frame_sz & 15)
      frame_sz = (frame_sz + 15) & ~15;
    jit_sub_rsp(j, frame_sz);
  }
}

static void jit_epilog_frame(jit_buf* j) {
  jit_mov_rr64(j, RSP, RBP);
  jit_pop_r64(j, RBP);
  jit_ret(j);
}

#define jit_prolog jit_prolog_x64
#define jit_epilog jit_epilog_x64

#define jit_add32 jit_add_rr32
#define jit_add64 jit_add_rr64
#define jit_sub32 jit_sub_rr32
#define jit_sub64 jit_sub_rr64
#define jit_and32 jit_and_rr32
#define jit_and64 jit_and_rr64
#define jit_or32 jit_or_rr32
#define jit_or64 jit_or_rr64
#define jit_xor32 jit_xor_rr32
#define jit_xor64 jit_xor_rr64
#define jit_mul32 jit_imul_rr32
#define jit_mul64 jit_imul_rr64

#endif

#elif JIT_ARCH == JIT_ARCH_ARM64

typedef enum {
  X0 = 0,
  X1,
  X2,
  X3,
  X4,
  X5,
  X6,
  X7,
  X8,
  X9,
  X10,
  X11,
  X12,
  X13,
  X14,
  X15,
  X16,
  X17,
  X18,
  X19,
  X20,
  X21,
  X22,
  X23,
  X24,
  X25,
  X26,
  X27,
  X28,
  X29,
  X30,
  XZR = 31,
  SP = 31
} jit_reg;

static void a64_emit(jit_buf* j, u32 ins) {
  jit_ensure(j, 4);
  j->buf[j->len + 0] = (u8)(ins);
  j->buf[j->len + 1] = (u8)(ins >> 8);
  j->buf[j->len + 2] = (u8)(ins >> 16);
  j->buf[j->len + 3] = (u8)(ins >> 24);
  j->len += 4;
}

static void jit_mov_rr64(jit_buf* j, int dst, int src) {
  a64_emit(j, 0xAA0003E0 | ((u32)(src & 31) << 16) | (u32)(dst & 31));
}

static void jit_mov_ri64(jit_buf* j, int dst, i64 imm) {
  u16 h0 = (u16)(imm);
  u16 h1 = (u16)(imm >> 16);
  u16 h2 = (u16)(imm >> 32);
  u16 h3 = (u16)(imm >> 48);
  a64_emit(j, 0xD2800000 | ((u32)h0 << 5) | (u32)(dst & 31));
  if (h1)
    a64_emit(j, 0xF2A00000 | ((u32)h1 << 5) | (u32)(dst & 31));
  if (h2)
    a64_emit(j, 0xF2C00000 | ((u32)h2 << 5) | (u32)(dst & 31));
  if (h3)
    a64_emit(j, 0xF2E00000 | ((u32)h3 << 5) | (u32)(dst & 31));
}

static void jit_mov_ri32(jit_buf* j, int dst, i32 imm) {
  u16 lo = (u16)imm;
  u16 hi = (u16)((u32)imm >> 16);
  a64_emit(j, 0x52800000 | ((u32)lo << 5) | (u32)(dst & 31));
  if (hi)
    a64_emit(j, 0x72A00000 | ((u32)hi << 5) | (u32)(dst & 31));
}

static void jit_add_rr64(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0x8B000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_sub_rr64(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0xCB000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_and_rr64(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0x8A000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_or_rr64(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0xAA000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_xor_rr64(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0xCA000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_mul_rr64(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0x9B007C00 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_add_rr32(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0x0B000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_sub_rr32(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0x4B000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_and_rr32(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0x0A000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_or_rr32(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0x2A000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_xor_rr32(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0x4A000000 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_mul_rr32(jit_buf* j, int d, int a, int b) {
  a64_emit(j, 0x1B007C00 | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5) |
                  (u32)(d & 31));
}

static void jit_neg_r64(jit_buf* j, int d, int s) {
  a64_emit(j, 0xCB0003E0 | ((u32)(s & 31) << 16) | (u32)(d & 31));
}

static void jit_neg_r32(jit_buf* j, int d, int s) {
  a64_emit(j, 0x4B0003E0 | ((u32)(s & 31) << 16) | (u32)(d & 31));
}

static void jit_not_r64(jit_buf* j, int d, int s) {
  a64_emit(j, 0xAA2003E0 | ((u32)(s & 31) << 16) | (u32)(d & 31));
}

static void jit_ldr64(jit_buf* j, int dst, int base, i32 off) {
  if (off >= 0 && off < 32768 && (off & 7) == 0) {
    a64_emit(j, 0xF9400000 | ((u32)(off / 8) << 10) | ((u32)(base & 31) << 5) |
                    (u32)(dst & 31));
  } else {
    a64_emit(j, 0xF8400000 | ((u32)(off & 0x1FF) << 12) |
                    ((u32)(base & 31) << 5) | (u32)(dst & 31));
  }
}

static void jit_str64(jit_buf* j, int src, int base, i32 off) {
  if (off >= 0 && off < 32768 && (off & 7) == 0) {
    a64_emit(j, 0xF9000000 | ((u32)(off / 8) << 10) | ((u32)(base & 31) << 5) |
                    (u32)(src & 31));
  } else {
    a64_emit(j, 0xF8000000 | ((u32)(off & 0x1FF) << 12) |
                    ((u32)(base & 31) << 5) | (u32)(src & 31));
  }
}

static void jit_ldr32(jit_buf* j, int dst, int base, i32 off) {
  if (off >= 0 && off < 16384 && (off & 3) == 0) {
    a64_emit(j, 0xB9400000 | ((u32)(off / 4) << 10) | ((u32)(base & 31) << 5) |
                    (u32)(dst & 31));
  } else {
    a64_emit(j, 0xB8400000 | ((u32)(off & 0x1FF) << 12) |
                    ((u32)(base & 31) << 5) | (u32)(dst & 31));
  }
}

static void jit_str32(jit_buf* j, int src, int base, i32 off) {
  if (off >= 0 && off < 16384 && (off & 3) == 0) {
    a64_emit(j, 0xB9000000 | ((u32)(off / 4) << 10) | ((u32)(base & 31) << 5) |
                    (u32)(src & 31));
  } else {
    a64_emit(j, 0xB8000000 | ((u32)(off & 0x1FF) << 12) |
                    ((u32)(base & 31) << 5) | (u32)(src & 31));
  }
}

static void jit_cmp_rr64(jit_buf* j, int a, int b) {
  a64_emit(j, 0xEB00001F | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5));
}

static void jit_cmp_rr32(jit_buf* j, int a, int b) {
  a64_emit(j, 0x6B00001F | ((u32)(b & 31) << 16) | ((u32)(a & 31) << 5));
}

static void jit_shl_ri64(jit_buf* j, int d, int s, u8 sh) {
  u8 immr = (64 - sh) & 63;
  u8 imms = 63 - sh;
  a64_emit(j, 0xD3400000 | ((u32)immr << 16) | ((u32)imms << 10) |
                  ((u32)(s & 31) << 5) | (u32)(d & 31));
}

static void jit_shr_ri64(jit_buf* j, int d, int s, u8 sh) {
  a64_emit(j, 0xD3400000 | ((u32)(sh) << 16) | (0x3F << 10) |
                  ((u32)(s & 31) << 5) | (u32)(d & 31));
}

static void jit_sar_ri64(jit_buf* j, int d, int s, u8 sh) {
  a64_emit(j, 0x93400000 | ((u32)(sh) << 16) | (0x3F << 10) |
                  ((u32)(s & 31) << 5) | (u32)(d & 31));
}

static void jit_b_lbl(jit_buf* j, int lbl) {
  jit_add_fixup(j, j->len, lbl, 4);
  a64_emit(j, 0x14000000);
}

static void jit_bl_abs(jit_buf* j, int tmp, void* fn) {
  jit_mov_ri64(j, tmp, (i64)(uintptr_t)fn);
  a64_emit(j, 0xD63F0000 | ((u32)(tmp & 31) << 5));
}

static void jit_ret(jit_buf* j) {
  a64_emit(j, 0xD65F03C0);
}

static void jit_nop(jit_buf* j) {
  a64_emit(j, 0xD503201F);
}

static void jit_prolog(jit_buf* j) {
  a64_emit(j, 0xA9BF7BFD);
  a64_emit(j, 0x910003FD);
}

static void jit_epilog(jit_buf* j) {
  a64_emit(j, 0xA8C17BFD);
  jit_ret(j);
}

static void jit_jcc_lbl(jit_buf* j, jit_cc cc, int lbl) {
  static const u8 a64_cc[] = {0, 1, 11, 13, 12, 10, 3, 9, 8, 2};
  jit_add_fixup(j, j->len, lbl, 4);
  a64_emit(j, 0x54000000 | (u32)(a64_cc[cc] & 15));
}

#endif

#if JIT_ARCH == JIT_ARCH_ARM32

typedef enum {
  R0 = 0,
  R1,
  R2,
  R3,
  R4,
  R5,
  R6,
  R7,
  R8,
  R9,
  R10,
  R11,
  R12,
  R13,
  R14,
  R15,
  SP = 13,
  LR = 14,
  PC = 15
} jit_reg;

static void a32_emit(jit_buf* j, u32 ins) {
  jit_ensure(j, 4);
  j->buf[j->len + 0] = (u8)(ins);
  j->buf[j->len + 1] = (u8)(ins >> 8);
  j->buf[j->len + 2] = (u8)(ins >> 16);
  j->buf[j->len + 3] = (u8)(ins >> 24);
  j->len += 4;
}

static void jit_mov_rr(jit_buf* j, int dst, int src) {
  a32_emit(j, 0xE1A00000 | ((u32)(dst & 15) << 12) | (u32)(src & 15));
}

static void jit_mov_ri(jit_buf* j, int dst, u32 imm) {
  if ((imm & 0xFF) == imm) {
    a32_emit(j, 0xE3A00000 | ((u32)(dst & 15) << 12) | imm);
  } else {
    a32_emit(j, 0xE3000000 | ((u32)(dst & 15) << 12) | (imm & 0xFFF) |
                    ((imm >> 12) << 16 & 0xF0000));
    if (imm >> 16) {
      a32_emit(j, 0xE3400000 | ((u32)(dst & 15) << 12) | ((imm >> 16) & 0xFFF) |
                      (((imm >> 28) & 0xF) << 16));
    }
  }
}

static void jit_add_rr(jit_buf* j, int d, int a, int b) {
  a32_emit(j, 0xE0800000 | ((u32)(d & 15) << 12) | ((u32)(a & 15) << 16) |
                  (u32)(b & 15));
}

static void jit_sub_rr(jit_buf* j, int d, int a, int b) {
  a32_emit(j, 0xE0400000 | ((u32)(d & 15) << 12) | ((u32)(a & 15) << 16) |
                  (u32)(b & 15));
}

static void jit_and_rr(jit_buf* j, int d, int a, int b) {
  a32_emit(j, 0xE0000000 | ((u32)(d & 15) << 12) | ((u32)(a & 15) << 16) |
                  (u32)(b & 15));
}

static void jit_or_rr(jit_buf* j, int d, int a, int b) {
  a32_emit(j, 0xE1800000 | ((u32)(d & 15) << 12) | ((u32)(a & 15) << 16) |
                  (u32)(b & 15));
}

static void jit_xor_rr(jit_buf* j, int d, int a, int b) {
  a32_emit(j, 0xE0200000 | ((u32)(d & 15) << 12) | ((u32)(a & 15) << 16) |
                  (u32)(b & 15));
}

static void jit_mul_rr(jit_buf* j, int d, int a, int b) {
  a32_emit(j, 0xE0000090 | ((u32)(d & 15) << 16) | ((u32)(b & 15) << 8) |
                  (u32)(a & 15));
}

static void jit_ldr(jit_buf* j, int dst, int base, i32 off) {
  if (off >= 0)
    a32_emit(j, 0xE5900000 | ((u32)(base & 15) << 16) |
                    ((u32)(dst & 15) << 12) | (u32)(off & 0xFFF));
  else
    a32_emit(j, 0xE5100000 | ((u32)(base & 15) << 16) |
                    ((u32)(dst & 15) << 12) | (u32)((-off) & 0xFFF));
}

static void jit_str(jit_buf* j, int src, int base, i32 off) {
  if (off >= 0)
    a32_emit(j, 0xE5800000 | ((u32)(base & 15) << 16) |
                    ((u32)(src & 15) << 12) | (u32)(off & 0xFFF));
  else
    a32_emit(j, 0xE5000000 | ((u32)(base & 15) << 16) |
                    ((u32)(src & 15) << 12) | (u32)((-off) & 0xFFF));
}

static void jit_cmp_rr(jit_buf* j, int a, int b) {
  a32_emit(j, 0xE1500000 | ((u32)(a & 15) << 16) | (u32)(b & 15));
}

static void jit_b_lbl(jit_buf* j, int lbl) {
  jit_add_fixup(j, j->len, lbl, 4);
  a32_emit(j, 0xEA000000);
}

static void jit_bl_abs(jit_buf* j, int tmp, void* fn) {
  jit_mov_ri(j, tmp, (u32)(uintptr_t)fn);
  a32_emit(j, 0xE12FFF30 | (u32)(tmp & 15));
}

static void jit_ret(jit_buf* j) {
  a32_emit(j, 0xE12FFF1E);
}

static void jit_nop(jit_buf* j) {
  a32_emit(j, 0xE320F000);
}

static void jit_prolog(jit_buf* j) {
  a32_emit(j, 0xE92D4800);
  a32_emit(j, 0xE28DB000);
}

static void jit_epilog(jit_buf* j) {
  a32_emit(j, 0xE8BD8800);
}

static void jit_jcc_lbl(jit_buf* j, jit_cc cc, int lbl) {
  static const u8 a32_cc[] = {0, 1, 11, 13, 12, 10, 3, 9, 8, 2};
  jit_add_fixup(j, j->len, lbl, 4);
  a32_emit(j, ((u32)(a32_cc[cc] & 15) << 28));
}

static void jit_shl_ri(jit_buf* j, int d, int s, u8 sh) {
  a32_emit(j, 0xE1A00000 | ((u32)(d & 15) << 12) | ((u32)(sh & 31) << 7) |
                  (u32)(s & 15));
}

static void jit_shr_ri(jit_buf* j, int d, int s, u8 sh) {
  a32_emit(j, 0xE1A00020 | ((u32)(d & 15) << 12) | ((u32)(sh & 31) << 7) |
                  (u32)(s & 15));
}

static void jit_sar_ri(jit_buf* j, int d, int s, u8 sh) {
  a32_emit(j, 0xE1A00040 | ((u32)(d & 15) << 12) | ((u32)(sh & 31) << 7) |
                  (u32)(s & 15));
}

#endif

#if JIT_ARCH == JIT_ARCH_X86_32

typedef enum {
  EAX_ = 0,
  ECX_ = 1,
  EDX_ = 2,
  EBX_ = 3,
  ESP_ = 4,
  EBP_ = 5,
  ESI_ = 6,
  EDI_ = 7
} jit_reg;

static void x86_modrm(jit_buf* j, int mod, int reg, int rm) {
  jit_emit1(j, (u8)((mod << 6) | ((reg & 7) << 3) | (rm & 7)));
}

static void jit_mov_rr32(jit_buf* j, int dst, int src) {
  jit_emit1(j, 0x8B);
  x86_modrm(j, 3, dst, src);
}

static void jit_mov_ri32(jit_buf* j, int dst, i32 imm) {
  jit_emit1(j, (u8)(0xB8 | dst));
  jit_emit_i32(j, imm);
}

static void jit_add_rr32(jit_buf* j, int d, int s) {
  jit_emit1(j, 0x03);
  x86_modrm(j, 3, d, s);
}

static void jit_sub_rr32(jit_buf* j, int d, int s) {
  jit_emit1(j, 0x2B);
  x86_modrm(j, 3, d, s);
}

static void jit_and_rr32(jit_buf* j, int d, int s) {
  jit_emit1(j, 0x23);
  x86_modrm(j, 3, d, s);
}

static void jit_or_rr32(jit_buf* j, int d, int s) {
  jit_emit1(j, 0x0B);
  x86_modrm(j, 3, d, s);
}

static void jit_xor_rr32(jit_buf* j, int d, int s) {
  jit_emit1(j, 0x33);
  x86_modrm(j, 3, d, s);
}

static void jit_imul_rr32(jit_buf* j, int d, int s) {
  jit_emit2(j, 0x0F, 0xAF);
  x86_modrm(j, 3, d, s);
}

static void jit_cmp_rr32(jit_buf* j, int a, int b) {
  jit_emit1(j, 0x3B);
  x86_modrm(j, 3, a, b);
}

static void jit_cmp_ri32(jit_buf* j, int a, i32 imm) {
  jit_emit1(j, 0x81);
  x86_modrm(j, 3, 7, a);
  jit_emit_i32(j, imm);
}

static void jit_jmp_lbl(jit_buf* j, int lbl) {
  jit_emit1(j, 0xE9);
  jit_add_fixup(j, j->len, lbl, 4);
  jit_emit_i32(j, 0);
}

static void jit_jcc_lbl(jit_buf* j, jit_cc cc, int lbl) {
  static const u8 jcc_ops[] = {0x84, 0x85, 0x8C, 0x8E, 0x8F,
                               0x8D, 0x82, 0x86, 0x87, 0x83};
  jit_emit2(j, 0x0F, jcc_ops[cc]);
  jit_add_fixup(j, j->len, lbl, 4);
  jit_emit_i32(j, 0);
}

static void jit_call_r32(jit_buf* j, int r) {
  jit_emit1(j, 0xFF);
  x86_modrm(j, 3, 2, r);
}

static void jit_call_abs(jit_buf* j, void* fn) {
  jit_mov_ri32(j, EAX_, (i32)(uintptr_t)fn);
  jit_call_r32(j, EAX_);
}

static void jit_push_r32(jit_buf* j, int r) {
  jit_emit1(j, (u8)(0x50 | r));
}

static void jit_pop_r32(jit_buf* j, int r) {
  jit_emit1(j, (u8)(0x58 | r));
}

static void jit_ret(jit_buf* j) {
  jit_emit1(j, 0xC3);
}

static void jit_nop(jit_buf* j) {
  jit_emit1(j, 0x90);
}

static void jit_prolog(jit_buf* j) {
  jit_push_r32(j, EBP_);
  jit_emit2(j, 0x89, 0xE5);
}

static void jit_epilog(jit_buf* j) {
  jit_emit2(j, 0x89, 0xEC);
  jit_pop_r32(j, EBP_);
  jit_ret(j);
}

static void jit_neg_r32(jit_buf* j, int r) {
  jit_emit1(j, 0xF7);
  x86_modrm(j, 3, 3, r);
}

static void jit_not_r32(jit_buf* j, int r) {
  jit_emit1(j, 0xF7);
  x86_modrm(j, 3, 2, r);
}

static void jit_shl_ri32(jit_buf* j, int r, u8 sh) {
  jit_emit1(j, 0xC1);
  x86_modrm(j, 3, 4, r);
  jit_emit1(j, sh);
}

static void jit_shr_ri32(jit_buf* j, int r, u8 sh) {
  jit_emit1(j, 0xC1);
  x86_modrm(j, 3, 5, r);
  jit_emit1(j, sh);
}

static void jit_sar_ri32(jit_buf* j, int r, u8 sh) {
  jit_emit1(j, 0xC1);
  x86_modrm(j, 3, 7, r);
  jit_emit1(j, sh);
}

static void jit_mov_rm32(jit_buf* j, int dst, int base, i32 disp) {
  jit_emit1(j, 0x8B);
  if (disp == 0) {
    x86_modrm(j, 0, dst, base);
  } else if (disp >= -128 && disp <= 127) {
    x86_modrm(j, 1, dst, base);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x86_modrm(j, 2, dst, base);
    jit_emit_i32(j, disp);
  }
}

static void jit_mov_mr32(jit_buf* j, int base, i32 disp, int src) {
  jit_emit1(j, 0x89);
  if (disp == 0) {
    x86_modrm(j, 0, src, base);
  } else if (disp >= -128 && disp <= 127) {
    x86_modrm(j, 1, src, base);
    jit_emit1(j, (u8)(i8)disp);
  } else {
    x86_modrm(j, 2, src, base);
    jit_emit_i32(j, disp);
  }
}

static void jit_idiv_r32(jit_buf* j, int src) {
  jit_emit1(j, 0xF7);
  x86_modrm(j, 3, 7, src);
}

static void jit_div_r32(jit_buf* j, int src) {
  jit_emit1(j, 0xF7);
  x86_modrm(j, 3, 6, src);
}

static void jit_cdq(jit_buf* j) {
  jit_emit1(j, 0x99);
}

#endif

static void* jit_compile(jit_buf* j) {
  jit_patch(j);
  jit_flush(j);
  return jit_fn(j);
}

#ifdef __cplusplus
}
#endif
#endif
