#ifndef NND_DISASM_H
#define NND_DISASM_H
/* C shim over binutils libopcodes — one instruction in, text+targets out. */

#ifdef __cplusplus
extern "C" {
#endif

struct nnd_insn_out {
  char text[512];                 /* mnemonic + operands, no address prefix */
  int len;                        /* bytes consumed; <=0 if invalid */
  int ntargets;
  unsigned long long targets[4];  /* address operands (via print_address_func) */
  int insn_type;                  /* enum dis_insn_type from dis-asm.h */
  unsigned long long branch_hint;/* info->target when set by the decoder */
};

/* arch: 0 = x86_64 (intel syntax), 1 = aarch64, 2 = riscv64.
   Returns 0 on success, -1 on failure. */
int nnd_disasm_one(int arch, unsigned long long addr,
                   const unsigned char *buf, int buflen,
                   struct nnd_insn_out *out);

#ifdef __cplusplus
}
#endif
#endif
