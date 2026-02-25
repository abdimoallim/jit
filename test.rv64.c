#include <stdio.h>
#define JIT_ARCH JIT_ARCH_RV64 /* skip annoying x64 errors */
#include "jit.h"

static int pass = 0;
static int fail = 0;

#define CHECK(name, got, expected)                                             \
  do {                                                                         \
    if ((got) == (expected)) {                                                 \
      printf("[PASS] %s\n", name);                                             \
      pass++;                                                                  \
    } else {                                                                   \
      printf("[FAIL] %s: got %lld, expected %lld\n", name, (long long)(got),   \
             (long long)(expected));                                           \
      fail++;                                                                  \
    }                                                                          \
  } while (0)

typedef i64 (*fn0)(void);
typedef i64 (*fn1)(i64);
typedef i64 (*fn2)(i64, i64);
typedef i64 (*fn3)(i64, i64, i64);

static void test_ret_const(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_ri64(&j, A0, 42);
  jit_epilog(&j);
  fn0 f = (fn0)jit_compile(&j);
  CHECK("ret_const", f(), 42);
  jit_free(&j);
}

static void test_ret_large_const(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_ri64(&j, A0, 0x123456789ABCLL);
  jit_epilog(&j);
  fn0 f = (fn0)jit_compile(&j);
  CHECK("ret_large_const", f(), 0x123456789ABCLL);
  jit_free(&j);
}

static void test_add(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_add_rr64(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("add 3+5", f(3, 5), 8);
  CHECK("add -1+1", f(-1, 1), 0);
  CHECK("add 100+200", f(100, 200), 300);
  jit_free(&j);
}

static void test_sub(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_sub_rr64(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("sub 10-3", f(10, 3), 7);
  CHECK("sub 0-5", f(0, 5), -5);
  jit_free(&j);
}

static void test_mul(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mul_rr64(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("mul 6*7", f(6, 7), 42);
  CHECK("mul -3*4", f(-3, 4), -12);
  CHECK("mul 0*999", f(0, 999), 0);
  jit_free(&j);
}

static void test_div(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_div_rr64(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("div 20/4", f(20, 4), 5);
  CHECK("div -20/4", f(-20, 4), -5);
  CHECK("div 100/7", f(100, 7), 14);
  jit_free(&j);
}

static void test_rem(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_rem_rr64(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("rem 10%3", f(10, 3), 1);
  CHECK("rem 100%7", f(100, 7), 2);
  jit_free(&j);
}

static void test_and_or_xor(void) {
  jit_buf j;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_and_rr64(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 fa = (fn2)jit_compile(&j);
  CHECK("and 0xF0&0xFF", fa(0xF0, 0xFF), 0xF0);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_or_rr64(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 fo = (fn2)jit_compile(&j);
  CHECK("or 0xF0|0x0F", fo(0xF0, 0x0F), 0xFF);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_xor_rr64(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 fx = (fn2)jit_compile(&j);
  CHECK("xor 0xFF^0x0F", fx(0xFF, 0x0F), 0xF0);
  jit_free(&j);
}

static void test_neg_not(void) {
  jit_buf j;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_neg_r64(&j, A0, A0);
  jit_epilog(&j);
  fn1 fn = (fn1)jit_compile(&j);
  CHECK("neg 5", fn(5), -5);
  CHECK("neg -3", fn(-3), 3);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_not_r64(&j, A0, A0);
  jit_epilog(&j);
  fn1 fnot = (fn1)jit_compile(&j);
  CHECK("not 0", fnot(0), -1);
  jit_free(&j);
}

static void test_shift(void) {
  jit_buf j;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_shl_ri64(&j, A0, A0, 3);
  jit_epilog(&j);
  fn1 fsl = (fn1)jit_compile(&j);
  CHECK("shl 1<<3", fsl(1), 8);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_shr_ri64(&j, A0, A0, 2);
  jit_epilog(&j);
  fn1 fsr = (fn1)jit_compile(&j);
  CHECK("shr 64>>2", fsr(64), 16);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_sar_ri64(&j, A0, A0, 1);
  jit_epilog(&j);
  fn1 fsa = (fn1)jit_compile(&j);
  CHECK("sar -8>>1", fsa(-8), -4);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_shl_rr64(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 fslr = (fn2)jit_compile(&j);
  CHECK("shl_rr 1<<4", fslr(1, 4), 16);
  jit_free(&j);
}

static void test_slt(void) {
  jit_buf j;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_slt_rr(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("slt 3<5", f(3, 5), 1);
  CHECK("slt 5<3", f(5, 3), 0);
  CHECK("slt 5<5", f(5, 5), 0);
  CHECK("slt -1<0", f(-1, 0), 1);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_sltu_rr(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 fu = (fn2)jit_compile(&j);
  CHECK("sltu 3<5", fu(3, 5), 1);
  jit_free(&j);
}

static void test_branch_if(void) {
  jit_buf j;
  int lbl_true, lbl_end;

  jit_init(&j, 0);
  jit_prolog(&j);
  lbl_true = jit_label(&j);
  lbl_end = jit_label(&j);
  jit_jcc_lbl(&j, JIT_CC_GT, A0, ZERO, lbl_true);
  jit_mov_ri64(&j, A0, 0);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_true);
  jit_mov_ri64(&j, A0, 1);
  jit_bind(&j, lbl_end);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("branch >0 -> 1", f(5), 1);
  CHECK("branch <=0 -> 0", f(-1), 0);
  CHECK("branch 0 -> 0", f(0), 0);
  jit_free(&j);
}

static void test_branch_eq(void) {
  jit_buf j;
  int lbl_eq, lbl_end;

  jit_init(&j, 0);
  jit_prolog(&j);
  lbl_eq = jit_label(&j);
  lbl_end = jit_label(&j);
  jit_jcc_lbl(&j, JIT_CC_EQ, A0, A1, lbl_eq);
  jit_mov_ri64(&j, A0, 0);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_eq);
  jit_mov_ri64(&j, A0, 1);
  jit_bind(&j, lbl_end);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("branch eq 5==5", f(5, 5), 1);
  CHECK("branch eq 5==6", f(5, 6), 0);
  jit_free(&j);
}

static void test_loop_sum(void) {
  jit_buf j;
  int lbl_loop, lbl_end;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, T0, A0);
  jit_mov_ri64(&j, A0, 0);
  jit_mov_ri64(&j, T1, 0);
  lbl_loop = jit_label(&j);
  lbl_end = jit_label(&j);
  jit_bind(&j, lbl_loop);
  jit_jcc_lbl(&j, JIT_CC_GE, T1, T0, lbl_end);
  jit_add_rr64(&j, A0, A0, T1);
  jit_add_ri64(&j, T1, T1, 1);
  jit_jmp_lbl(&j, lbl_loop);
  jit_bind(&j, lbl_end);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("loop sum 0..10", f(10), 45);
  CHECK("loop sum 0..0", f(0), 0);
  CHECK("loop sum 0..100", f(100), 4950);
  jit_free(&j);
}

static void test_factorial(void) {
  jit_buf j;
  int lbl_loop, lbl_end;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, T0, A0);
  jit_mov_ri64(&j, A0, 1);
  lbl_loop = jit_label(&j);
  lbl_end = jit_label(&j);
  jit_bind(&j, lbl_loop);
  jit_mov_ri64(&j, T1, 1);
  jit_jcc_lbl(&j, JIT_CC_LE, T0, T1, lbl_end);
  jit_mul_rr64(&j, A0, A0, T0);
  jit_add_ri64(&j, T0, T0, -1);
  jit_jmp_lbl(&j, lbl_loop);
  jit_bind(&j, lbl_end);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("factorial 1", f(1), 1);
  CHECK("factorial 5", f(5), 120);
  CHECK("factorial 10", f(10), 3628800);
  jit_free(&j);
}

/**
  * changed from fp-8 to fp-24. fp-8 and fp-16 are reserved for
  * the saved RA and FP, user locals must start at fp-24 and below.
 */
static void test_stack_locals(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog_frame(&j, 16);
  jit_add_rr64(&j, T0, A0, A1);
  jit_sd64(&j, T0, FP, -24);
  jit_mov_ri64(&j, A0, 0);
  jit_ld64(&j, A0, FP, -24);
  jit_epilog_frame(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("stack local 10+20", f(10, 20), 30);
  CHECK("stack local 0+0", f(0, 0), 0);
  jit_free(&j);
}

static void test_mem_rw(void) {
  i64 arr[4] = {10, 20, 30, 40};
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_ld64(&j, T0, A0, 0);
  jit_ld64(&j, T1, A0, 8);
  jit_ld64(&j, T2, A0, 16);
  jit_add_rr64(&j, A0, T0, T1);
  jit_add_rr64(&j, A0, A0, T2);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("mem_rw arr[0+1+2]", f((i64)(uintptr_t)arr), 60);
  jit_free(&j);
}

static void test_mem_store(void) {
  i64 dst = 0;
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_ri64(&j, T0, 12345);
  jit_sd64(&j, T0, A0, 0);
  jit_mov_ri64(&j, A0, 0);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  f((i64)(uintptr_t)&dst);
  CHECK("mem_store 12345", dst, 12345);
  jit_free(&j);
}

static void test_imm_arithmetic(void) {
  jit_buf j;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_add_ri64(&j, A0, A0, 10);
  jit_epilog(&j);
  fn1 fa = (fn1)jit_compile(&j);
  CHECK("add_imm 5+10", fa(5), 15);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_and_ri64(&j, A0, A0, 0x0F);
  jit_epilog(&j);
  fn1 fand = (fn1)jit_compile(&j);
  CHECK("and_imm 0xFF&0x0F", fand(0xFF), 0x0F);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_or_ri64(&j, A0, A0, 0x10);
  jit_epilog(&j);
  fn1 forr = (fn1)jit_compile(&j);
  CHECK("or_imm 0x01|0x10", forr(0x01), 0x11);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_xor_ri64(&j, A0, A0, 0xFF);
  jit_epilog(&j);
  fn1 fxor = (fn1)jit_compile(&j);
  CHECK("xor_imm 0xF0^0xFF", fxor(0xF0), 0x0F);
  jit_free(&j);
}

static void test_call_c(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_ri64(&j, A0, (i64)(uintptr_t)"hello from rv64 jit\n");
  jit_call_abs(&j, T0, (void*)puts);
  jit_mov_ri64(&j, A0, 99);
  jit_epilog(&j);
  fn0 f = (fn0)jit_compile(&j);
  i64 r = f();
  CHECK("call_c puts ret", r, 99);
  jit_free(&j);
}

static void test_multi_label(void) {
  jit_buf j;
  int lbl_a, lbl_b, lbl_c, lbl_end;

  jit_init(&j, 0);
  jit_prolog(&j);
  lbl_a = jit_label(&j);
  lbl_b = jit_label(&j);
  lbl_c = jit_label(&j);
  lbl_end = jit_label(&j);

  jit_mov_ri64(&j, T0, 1);
  jit_jcc_lbl(&j, JIT_CC_EQ, A0, T0, lbl_a);
  jit_mov_ri64(&j, T0, 2);
  jit_jcc_lbl(&j, JIT_CC_EQ, A0, T0, lbl_b);
  jit_mov_ri64(&j, T0, 3);
  jit_jcc_lbl(&j, JIT_CC_EQ, A0, T0, lbl_c);
  jit_mov_ri64(&j, A0, 0);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_a);
  jit_mov_ri64(&j, A0, 100);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_b);
  jit_mov_ri64(&j, A0, 200);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_c);
  jit_mov_ri64(&j, A0, 300);
  jit_bind(&j, lbl_end);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("multi_lbl case 1", f(1), 100);
  CHECK("multi_lbl case 2", f(2), 200);
  CHECK("multi_lbl case 3", f(3), 300);
  CHECK("multi_lbl default", f(99), 0);
  jit_free(&j);
}

static void test_w_ops(void) {
  jit_buf j;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_add_rr32(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 fadd = (fn2)jit_compile(&j);
  CHECK("addw 7+3", fadd(7, 3), 10);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_sub_rr32(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 fsub = (fn2)jit_compile(&j);
  CHECK("subw 10-3", fsub(10, 3), 7);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mul_rr32(&j, A0, A0, A1);
  jit_epilog(&j);
  fn2 fmul = (fn2)jit_compile(&j);
  CHECK("mulw 6*7", fmul(6, 7), 42);
  jit_free(&j);
}

static void test_grow(void) {
  jit_buf j;
  int i;
  jit_init(&j, 32);
  jit_prolog(&j);
  jit_mov_ri64(&j, A0, 0);
  for (i = 0; i < 50; i++) {
    jit_add_ri64(&j, A0, A0, 1);
  }
  jit_epilog(&j);
  fn0 f = (fn0)jit_compile(&j);
  CHECK("grow buf 50 adds", f(), 50);
  jit_free(&j);
}

int main(void) {
  printf("=== jit test suite (rv64) ===\n\n");
  test_ret_const();
  test_ret_large_const();
  test_add();
  test_sub();
  test_mul();
  test_div();
  test_rem();
  test_and_or_xor();
  test_neg_not();
  test_shift();
  test_slt();
  test_branch_if();
  test_branch_eq();
  test_loop_sum();
  test_factorial();
  test_stack_locals();
  test_mem_rw();
  test_mem_store();
  test_imm_arithmetic();
  test_call_c();
  test_multi_label();
  test_w_ops();
  test_grow();
  printf("\n=== results: %d passed, %d failed ===\n", pass, fail);
  return fail ? 1 : 0;
}
