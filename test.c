#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
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
  jit_mov_ri64(&j, RAX, 42);
  jit_epilog(&j);
  fn0 f = (fn0)jit_compile(&j);
  CHECK("ret_const", f(), 42);
  jit_free(&j);
}

static void test_add(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_add_rr64(&j, RAX, RSI);
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
  jit_mov_rr64(&j, RAX, RDI);
  jit_sub_rr64(&j, RAX, RSI);
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
  jit_mov_rr64(&j, RAX, RDI);
  jit_imul_rr64(&j, RAX, RSI);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("mul 6*7", f(6, 7), 42);
  CHECK("mul -3*4", f(-3, 4), -12);
  jit_free(&j);
}

static void test_and_or_xor(void) {
  jit_buf j;
  jit_init(&j, 0);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_and_rr64(&j, RAX, RSI);
  jit_epilog(&j);
  fn2 fa = (fn2)jit_compile(&j);
  CHECK("and 0xF0 & 0xFF", fa(0xF0, 0xFF), 0xF0);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_or_rr64(&j, RAX, RSI);
  jit_epilog(&j);
  fn2 fo = (fn2)jit_compile(&j);
  CHECK("or 0xF0 | 0x0F", fo(0xF0, 0x0F), 0xFF);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_xor_rr64(&j, RAX, RSI);
  jit_epilog(&j);
  fn2 fx = (fn2)jit_compile(&j);
  CHECK("xor 0xFF ^ 0x0F", fx(0xFF, 0x0F), 0xF0);
  jit_free(&j);
}

static void test_shift(void) {
  jit_buf j;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_shl_ri64(&j, RAX, RAX, 3);
  jit_epilog(&j);
  fn1 fsl = (fn1)jit_compile(&j);
  CHECK("shl 1<<3", fsl(1), 8);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_shr_ri64(&j, RAX, RAX, 2);
  jit_epilog(&j);
  fn1 fsr = (fn1)jit_compile(&j);
  CHECK("shr 64>>2", fsr(64), 16);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_sar_ri64(&j, RAX, RAX, 1);
  jit_epilog(&j);
  fn1 fsa = (fn1)jit_compile(&j);
  CHECK("sar -8>>1", fsa(-8), -4);
  jit_free(&j);
}

static void test_neg_not(void) {
  jit_buf j;

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_neg_r64(&j, RAX);
  jit_epilog(&j);
  fn1 fn = (fn1)jit_compile(&j);
  CHECK("neg 5", fn(5), -5);
  CHECK("neg -3", fn(-3), 3);
  jit_free(&j);

  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_not_r64(&j, RAX);
  jit_epilog(&j);
  fn1 fnot = (fn1)jit_compile(&j);
  CHECK("not 0", fnot(0), -1);
  jit_free(&j);
}

static void test_div(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_cqo(&j);
  jit_idiv_r64(&j, RSI);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("idiv 20/4", f(20, 4), 5);
  CHECK("idiv -20/4", f(-20, 4), -5);
  jit_free(&j);
}

static void test_branch_if(void) {
  jit_buf j;
  int lbl_true, lbl_end;
  jit_init(&j, 0);
  jit_prolog(&j);
  lbl_true = jit_label(&j);
  lbl_end = jit_label(&j);
  jit_cmp_ri64(&j, RDI, 0);
  jit_jcc_lbl(&j, JIT_CC_GT, lbl_true);
  jit_mov_ri64(&j, RAX, 0);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_true);
  jit_mov_ri64(&j, RAX, 1);
  jit_bind(&j, lbl_end);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("branch >0 -> 1", f(5), 1);
  CHECK("branch <=0 -> 0", f(-1), 0);
  CHECK("branch 0 -> 0", f(0), 0);
  jit_free(&j);
}

static void test_loop_sum(void) {
  jit_buf j;
  int lbl_loop, lbl_end;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_ri64(&j, RAX, 0);
  jit_mov_ri64(&j, RCX, 0);
  lbl_loop = jit_label(&j);
  lbl_end = jit_label(&j);
  jit_bind(&j, lbl_loop);
  jit_cmp_rr64(&j, RCX, RDI);
  jit_jcc_lbl(&j, JIT_CC_GE, lbl_end);
  jit_add_rr64(&j, RAX, RCX);
  jit_add_ri64(&j, RCX, 1);
  jit_jmp_lbl(&j, lbl_loop);
  jit_bind(&j, lbl_end);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("loop sum 0..10", f(10), 45);
  CHECK("loop sum 0..0", f(0), 0);
  CHECK("loop sum 0..100", f(100), 4950);
  jit_free(&j);
}

static void test_stack_locals(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog_frame(&j, 16);
  jit_mov_rr64(&j, RAX, RDI);
  jit_add_rr64(&j, RAX, RSI);
  jit_mov_mr64(&j, RBP, -8, RAX);
  jit_mov_ri64(&j, RAX, 0);
  jit_mov_rm64(&j, RAX, RBP, -8);
  jit_epilog_frame(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("stack local", f(10, 20), 30);
  jit_free(&j);
}

static void test_call_c(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog_frame(&j, 0);
  jit_push_r64(&j, RBP);
  jit_sub_rsp(&j, 8);
  jit_mov_ri64(&j, RDI, (i64)(uintptr_t)"hello from jit\n");
  jit_call_abs(&j, (void*)puts);
  jit_add_rsp(&j, 8);
  jit_pop_r64(&j, RBP);
  jit_mov_ri64(&j, RAX, 99);
  jit_epilog_frame(&j);
  fn0 f = (fn0)jit_compile(&j);
  i64 r = f();
  CHECK("call_c puts ret", r, 99);
  jit_free(&j);
}

static void test_cmov(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_cmp_rr64(&j, RDI, RSI);
  jit_cmov_rr64(&j, JIT_CC_GT, RAX, RSI);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("cmov min(10,5)", f(10, 5), 5);
  CHECK("cmov min(3,7)", f(3, 7), 3);
  jit_free(&j);
}

static void test_fibonacci(void) {
  jit_buf j;
  int lbl_base, lbl_end;
  jit_init(&j, 0);
  jit_prolog_frame(&j, 16);
  lbl_base = jit_label(&j);
  lbl_end = jit_label(&j);
  jit_cmp_ri64(&j, RDI, 2);
  jit_jcc_lbl(&j, JIT_CC_LT, lbl_base);
  jit_mov_rr64(&j, RAX, RDI);
  jit_sub_ri64(&j, RAX, 1);
  jit_mov_mr64(&j, RBP, -8, RDI);
  jit_mov_rr64(&j, RDI, RAX);
  jit_call_abs(&j, jit_fn(&j));
  jit_mov_rr64(&j, RBX, RAX);
  jit_mov_rm64(&j, RDI, RBP, -8);
  jit_sub_ri64(&j, RDI, 2);
  jit_mov_mr64(&j, RBP, -8, RBX);
  jit_call_abs(&j, jit_fn(&j));
  jit_mov_rm64(&j, RCX, RBP, -8);
  jit_add_rr64(&j, RAX, RCX);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_base);
  jit_mov_rr64(&j, RAX, RDI);
  jit_bind(&j, lbl_end);
  jit_epilog_frame(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("fib(0)", f(0), 0);
  CHECK("fib(1)", f(1), 1);
  CHECK("fib(7)", f(7), 13);
  CHECK("fib(10)", f(10), 55);
  jit_free(&j);
}

static void test_popcnt(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr64(&j, RAX, RDI);
  jit_popcnt_r64(&j, RAX, RAX);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("popcnt 0xFF", f(0xFF), 8);
  CHECK("popcnt 0", f(0), 0);
  CHECK("popcnt 0b1010", f(0xA), 2);
  jit_free(&j);
}

static void test_bswap(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rr32(&j, EAX, EDI);
  jit_bswap_r32(&j, EAX);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("bswap32 0x01020304", f(0x01020304), (i64)(i32)0x04030201);
  jit_free(&j);
}

static void test_lea(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_lea_rm(&j, RAX, RDI, 16);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("lea base+16", f(100), 116);
  jit_free(&j);
}

static void test_setcc(void) {
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_cmp_rr64(&j, RDI, RSI);
  jit_mov_ri64(&j, RAX, 0);
  jit_setcc(&j, JIT_CC_EQ, RAX);
  jit_epilog(&j);
  fn2 f = (fn2)jit_compile(&j);
  CHECK("setcc eq 5==5", f(5, 5), 1);
  CHECK("setcc eq 5==6", f(5, 6), 0);
  jit_free(&j);
}

static void test_mem_rw(void) {
  i64 arr[4] = {10, 20, 30, 40};
  jit_buf j;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_rm64(&j, RAX, RDI, 0);
  jit_add_rm64(&j, RAX, RDI, 8);
  jit_add_rm64(&j, RAX, RDI, 16);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("mem_rw arr[0]+arr[1]+arr[2]", f((i64)(uintptr_t)arr), 60);
  jit_free(&j);
}

static void test_grow(void) {
  jit_buf j;
  int i;
  jit_init(&j, 32);
  jit_prolog(&j);
  jit_mov_ri64(&j, RAX, 0);
  for (i = 0; i < 50; i++) {
    jit_add_ri64(&j, RAX, 1);
  }
  jit_epilog(&j);
  fn0 f = (fn0)jit_compile(&j);
  CHECK("grow buf 50 adds", f(), 50);
  jit_free(&j);
}

static void test_factorial(void) {
  jit_buf j;
  int lbl_loop, lbl_end;
  jit_init(&j, 0);
  jit_prolog(&j);
  jit_mov_ri64(&j, RAX, 1);
  jit_mov_rr64(&j, RCX, RDI);
  lbl_loop = jit_label(&j);
  lbl_end = jit_label(&j);
  jit_bind(&j, lbl_loop);
  jit_cmp_ri64(&j, RCX, 1);
  jit_jcc_lbl(&j, JIT_CC_LE, lbl_end);
  jit_imul_rr64(&j, RAX, RCX);
  jit_sub_ri64(&j, RCX, 1);
  jit_jmp_lbl(&j, lbl_loop);
  jit_bind(&j, lbl_end);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("factorial 1", f(1), 1);
  CHECK("factorial 5", f(5), 120);
  CHECK("factorial 10", f(10), 3628800);
  jit_free(&j);
}

static void test_multi_label_branch(void) {
  jit_buf j;
  int lbl_a, lbl_b, lbl_c, lbl_end;
  jit_init(&j, 0);
  jit_prolog(&j);
  lbl_a = jit_label(&j);
  lbl_b = jit_label(&j);
  lbl_c = jit_label(&j);
  lbl_end = jit_label(&j);
  jit_cmp_ri64(&j, RDI, 1);
  jit_jcc_lbl(&j, JIT_CC_EQ, lbl_a);
  jit_cmp_ri64(&j, RDI, 2);
  jit_jcc_lbl(&j, JIT_CC_EQ, lbl_b);
  jit_cmp_ri64(&j, RDI, 3);
  jit_jcc_lbl(&j, JIT_CC_EQ, lbl_c);
  jit_mov_ri64(&j, RAX, 0);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_a);
  jit_mov_ri64(&j, RAX, 100);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_b);
  jit_mov_ri64(&j, RAX, 200);
  jit_jmp_lbl(&j, lbl_end);
  jit_bind(&j, lbl_c);
  jit_mov_ri64(&j, RAX, 300);
  jit_bind(&j, lbl_end);
  jit_epilog(&j);
  fn1 f = (fn1)jit_compile(&j);
  CHECK("multi_lbl case 1", f(1), 100);
  CHECK("multi_lbl case 2", f(2), 200);
  CHECK("multi_lbl case 3", f(3), 300);
  CHECK("multi_lbl default", f(99), 0);
  jit_free(&j);
}

int main(void) {
  printf("=== jit test suite (x86-64) ===\n\n");
  test_ret_const();
  test_add();
  test_sub();
  test_mul();
  test_and_or_xor();
  test_shift();
  test_neg_not();
  test_div();
  test_branch_if();
  test_loop_sum();
  test_stack_locals();
  test_call_c();
  test_cmov();
  test_popcnt();
  test_bswap();
  test_lea();
  test_setcc();
  test_mem_rw();
  test_grow();
  test_factorial();
  test_multi_label_branch();
  printf("\n=== results: %d passed, %d failed ===\n", pass, fail);
  return fail ? 1 : 0;
}
