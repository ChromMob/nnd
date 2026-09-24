#include "nnd_disasm.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* bfd.h insists PACKAGE/PACKAGE_VERSION (config.h) comes first. */
#ifndef PACKAGE
#define PACKAGE "nnd-libopcodes-shim"
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "2.47"
#endif

#include "dis-asm.h"
#include "disassemble.h"

struct nnd_ctx {
  struct nnd_insn_out *out;
  size_t text_len;
};

static int nnd_vfprintf(struct nnd_ctx *ctx, const char *fmt, va_list ap) {
  size_t avail = sizeof(ctx->out->text) - ctx->text_len;
  if (avail <= 1)
    return 0;
  int n = vsnprintf(ctx->out->text + ctx->text_len, avail, fmt, ap);
  if (n < 0)
    return 0;
  if ((size_t)n >= avail)
    n = (int)(avail - 1);
  ctx->text_len += (size_t)n;
  return n;
}

static int nnd_fprintf(void *stream, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = nnd_vfprintf((struct nnd_ctx *)stream, fmt, ap);
  va_end(ap);
  return n;
}

static int nnd_fprintf_styled(void *stream, enum disassembler_style style,
                              const char *fmt, ...) {
  (void)style;
  va_list ap;
  va_start(ap, fmt);
  int n = nnd_vfprintf((struct nnd_ctx *)stream, fmt, ap);
  va_end(ap);
  return n;
}

/* Record branch/data addresses and print a deterministic plain-hex form so
   tests do not depend on objdump-style zero padding or symbol resolution. */
static void nnd_print_address(bfd_vma addr, struct disassemble_info *info) {
  struct nnd_ctx *ctx = (struct nnd_ctx *)info->stream;
  struct nnd_insn_out *out = ctx->out;
  if (out->ntargets < (int)(sizeof(out->targets) / sizeof(out->targets[0])))
    out->targets[out->ntargets++] = (unsigned long long)addr;
  nnd_fprintf(info->stream, "0x%llx", (unsigned long long)addr);
}

/* Silence out-of-bounds reads: perror_memory would pollute out->text. */
static void nnd_memory_error(int status, bfd_vma memaddr,
                             struct disassemble_info *info) {
  (void)status;
  (void)memaddr;
  (void)info;
}

/* options must be mutable: targets may temporarily edit it while parsing. */
static int nnd_run(disassembler_ftype print_insn, unsigned long long addr,
                   const unsigned char *buf, int buflen, char *options,
                   unsigned long mach, struct nnd_insn_out *out) {
  if (!out || !buf || buflen <= 0)
    return -1;
  memset(out, 0, sizeof(*out));

  struct nnd_ctx ctx;
  ctx.out = out;
  ctx.text_len = 0;

  struct disassemble_info info;
  init_disassemble_info(&info, &ctx, nnd_fprintf, nnd_fprintf_styled);
  info.read_memory_func = buffer_read_memory;
  info.memory_error_func = nnd_memory_error;
  info.print_address_func = nnd_print_address;
  info.symbol_at_address_func = generic_symbol_at_address;
  info.buffer = (bfd_byte *)(uintptr_t)buf;
  info.buffer_vma = (bfd_vma)addr;
  info.buffer_length = (size_t)buflen;
  info.disassembler_options = options;
  info.mach = mach;

  int len = print_insn((bfd_vma)addr, &info);
  if (len <= 0) {
    out->text[0] = '\0';
    out->len = 0;
    out->ntargets = 0;
    return -1;
  }
  out->len = len;
  out->text[sizeof(out->text) - 1] = '\0';
  out->insn_type = (int)info.insn_type;
  return 0;
}

int nnd_disasm_x86_64(unsigned long long addr, const unsigned char *buf,
                      int buflen, struct nnd_insn_out *out) {
  static char intel_opts[] = "intel";
  /* bfd_mach_x64_32 covers long mode (64-bit operand default). */
  return nnd_run(print_insn_i386, addr, buf, buflen, intel_opts,
                 bfd_mach_x64_32, out);
}

int nnd_disasm_aarch64(unsigned long long addr, const unsigned char *buf,
                       int buflen, struct nnd_insn_out *out) {
  return nnd_run(print_insn_aarch64, addr, buf, buflen, NULL, 0, out);
}

int nnd_disasm_riscv64(unsigned long long addr, const unsigned char *buf,
                       int buflen, struct nnd_insn_out *out) {
  return nnd_run(print_insn_riscv, addr, buf, buflen, NULL, bfd_mach_riscv64,
                 out);
}
