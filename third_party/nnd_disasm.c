#include "nnd_disasm.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* bfd.h insists config.h (or at least PACKAGE) comes first. */
#ifndef PACKAGE
#define PACKAGE "nnd-libopcodes-shim"
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "2.47"
#endif

#include "dis-asm.h"

/* Per-arch entry points live in libopcodes but aren't all declared in dis-asm.h. */
extern int print_insn_i386(bfd_vma, disassemble_info *);
extern int print_insn_aarch64(bfd_vma, disassemble_info *);
extern int print_insn_riscv(bfd_vma, disassemble_info *);

struct nnd_cap {
  struct nnd_insn_out *out;
  size_t pos;
};

static void cap_append(struct nnd_cap *c, const char *tmp, int n) {
  if (n < 0)
    return;
  size_t w = (size_t)n;
  if (w >= sizeof c->out->text)
    w = sizeof c->out->text - 1;
  if (c->pos + w >= sizeof c->out->text)
    w = sizeof c->out->text - 1 - c->pos;
  memcpy(c->out->text + c->pos, tmp, w);
  c->pos += w;
  c->out->text[c->pos] = 0;
}

static int cap_fprintf(void *stream, const char *fmt, ...) {
  struct nnd_cap *c = (struct nnd_cap *)stream;
  char tmp[256];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  va_end(ap);
  cap_append(c, tmp, n);
  return n;
}

static int cap_styled(void *stream, enum disassembler_style style, const char *fmt, ...) {
  (void)style;
  struct nnd_cap *c = (struct nnd_cap *)stream;
  char tmp[256];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  va_end(ap);
  cap_append(c, tmp, n);
  return n;
}

static void cap_print_address(bfd_vma addr, struct disassemble_info *info) {
  struct nnd_cap *c = (struct nnd_cap *)info->stream;
  if (c->out->ntargets < 4)
    c->out->targets[c->out->ntargets++] = (unsigned long long)addr;
  cap_fprintf(info->stream, "0x%llx", (unsigned long long)addr);
}

int nnd_disasm_one(int arch, unsigned long long addr, const unsigned char *buf,
                   int buflen, struct nnd_insn_out *out) {
  if (!out || !buf || buflen <= 0)
    return -1;
  memset(out, 0, sizeof *out);
  out->insn_type = (int)dis_noninsn;

  struct nnd_cap cap;
  cap.out = out;
  cap.pos = 0;

  struct disassemble_info info;
  init_disassemble_info(&info, &cap, cap_fprintf, cap_styled);
  info.read_memory_func = buffer_read_memory;
  info.print_address_func = cap_print_address;
  info.buffer = (bfd_byte *)(uintptr_t)buf;
  info.buffer_vma = addr;
  info.buffer_length = (size_t)buflen;
  info.endian = BFD_ENDIAN_LITTLE;
  info.endian_code = BFD_ENDIAN_LITTLE;
  info.octets_per_byte = 1;
  info.skip_zeroes = 3;
  info.skip_zeroes_at_end = 3;

  int (*fn)(bfd_vma, disassemble_info *);
  char intel_opts[] = "intel";
  switch (arch) {
  case 0: /* x86_64, Intel syntax to match nnd's listings */
    info.arch = bfd_arch_i386;
    info.mach = bfd_mach_x86_64;
    info.disassembler_options = intel_opts;
    fn = print_insn_i386;
    break;
  case 1: /* aarch64 */
    info.arch = bfd_arch_aarch64;
    info.mach = 0;
    fn = print_insn_aarch64;
    break;
  case 2: /* riscv64 */
    info.arch = bfd_arch_riscv;
    info.mach = 64;
    fn = print_insn_riscv;
    break;
  default:
    return -1;
  }

  disassemble_init_for_target(&info);
  int len = fn((bfd_vma)addr, &info);
  if (len <= 0) {
    out->len = 0;
    return -1;
  }
  out->len = len;
  out->insn_type = (int)info.insn_type;
  if (info.insn_info_valid && info.target != 0) {
    out->branch_hint = (unsigned long long)info.target;
    if (out->ntargets == 0) {
      out->targets[0] = out->branch_hint;
      out->ntargets = 1;
    }
  }
  disassemble_free_target(&info);
  return 0;
}
