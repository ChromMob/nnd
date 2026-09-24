/* Stable C ABI over binutils libopcodes for nnd. */
#ifndef NND_DISASM_H
#define NND_DISASM_H

struct nnd_insn_out {
  char text[512];       /* instruction text: mnemonic + operands, no address prefix */
  int len;              /* bytes consumed; <=0 if invalid */
  int ntargets;
  unsigned long long targets[4]; /* addresses printed via print_address_func */
  int insn_type;        /* enum dis_insn_type */
};

/* Each returns 0 on success, -1 on failure. */
int nnd_disasm_x86_64(unsigned long long addr, const unsigned char *buf, int buflen,
                      struct nnd_insn_out *out);
int nnd_disasm_aarch64(unsigned long long addr, const unsigned char *buf, int buflen,
                       struct nnd_insn_out *out);
int nnd_disasm_riscv64(unsigned long long addr, const unsigned char *buf, int buflen,
                       struct nnd_insn_out *out);

#endif
