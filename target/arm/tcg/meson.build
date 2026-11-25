gen_a64 = [
  decodetree.process('a64.decode', extra_args: ['--static-decode=disas_a64']),
  decodetree.process('sve.decode', extra_args: '--decode=disas_sve'),
  decodetree.process('sme.decode', extra_args: '--decode=disas_sme'),
  decodetree.process('sme-fa64.decode', extra_args: '--static-decode=disas_sme_fa64'),
]

vfp_d = [
  decodetree.process('vfp.decode', extra_args: '--decode=disas_vfp'),
  decodetree.process('vfp-uncond.decode', extra_args: '--decode=disas_vfp_uncond'),
]

neon_d = [
  decodetree.process('neon-shared.decode', extra_args: '--decode=disas_neon_shared'),
  decodetree.process('neon-dp.decode', extra_args: '--decode=disas_neon_dp'),
  decodetree.process('neon-ls.decode', extra_args: '--decode=disas_neon_ls'),
]

mve_d = decodetree.process('mve.decode', extra_args: '--decode=disas_mve')

m_nocp_d = decodetree.process('m-nocp.decode', extra_args: '--decode=disas_m_nocp')

translate32_d = [
  decodetree.process('a32.decode', extra_args: '--static-decode=disas_a32'),
  decodetree.process('a32-uncond.decode', extra_args: '--static-decode=disas_a32_uncond'),
  decodetree.process('t32.decode', extra_args: '--static-decode=disas_t32'),
  decodetree.process('t16.decode', extra_args: ['-w', '16', '--static-decode=disas_t16']),
]

arm_ss.add(when: 'TARGET_AARCH64', if_true: gen_a64)

# Builds with RCG (see include/tcg/rcg.h) generate its gadgets for A64,
# a64-rcg-table.c.inc, the table rcg.c.inc picks them from, and
# a64-rcg.decode, the patterns of a64.decode that it has gadgets for, from
# which decodetree makes rcg.c.inc's decoder. The file list must match
# GADGET_FILES in rcg-gen.py, which imports rcg_core.py and tcti_memory.py
# and reads a64.decode, hence its dependencies.
if get_option('tcg_threaded_interpreter') or \
   get_option('tcg_hybrid') in ['tcti', 'runtime']
  a64_rcg_gadgets = custom_target('a64-rcg-gadgets',
                                  output: ['a64-rcg-table.c.inc',
                                           'a64-rcg.decode',
                                           'rcg_gadgets_addsub.c',
                                           'rcg_gadgets_logic.c',
                                           'rcg_gadgets_move.c',
                                           'rcg_gadgets_mul.c'],
                                  input: files('rcg-gen.py'),
                                  depend_files: [rcg_core, tcti_memory,
                                                 files('a64.decode')],
                                  command: [python, '@INPUT@', '--gadgets',
                                            '@OUTDIR@'])
  a64_rcg_decode = custom_target('decode-a64-rcg',
                                 output: 'decode-a64-rcg.c.inc',
                                 input: a64_rcg_gadgets[1],
                                 command: [python, files(
                                   meson.project_source_root() / 'scripts' /
                                   'decodetree.py'), '@INPUT@',
                                   '--static-decode=rcg_a64', '-o',
                                   '@OUTPUT@'])
  arm_system_ss.add(when: ['CONFIG_TCG', 'TARGET_AARCH64'],
                    if_true: [a64_rcg_gadgets[0], a64_rcg_gadgets[2],
                              a64_rcg_gadgets[3], a64_rcg_gadgets[4],
                              a64_rcg_gadgets[5], a64_rcg_decode])
endif
arm_stubs_ss.add(files('stubs32.c'))

arm_ss.add(files(
  'cpu32.c',
))

arm_ss.add(when: 'TARGET_AARCH64', if_true: files(
  'gengvec64.c',
  'translate-a64.c',
  'translate-sve.c',
  'translate-sme.c',
  'helper-a64.c',
  'mte_helper.c',
  'pauth_helper.c',
  'sme_helper.c',
  'sve_helper.c',
  'vec_helper64.c',
  'fp8_helper.c',
))

arm_common_system_ss.add(when: 'CONFIG_ARM_V7M', if_true: files('cpu-v7m.c'))
arm_user_ss.add(when: 'TARGET_AARCH64', if_false: files('cpu-v7m.c'))

arm_common_ss.add(zlib)
arm_common_ss.add(files(
  'arith_helper.c',
  'crypto_helper.c',
  'idau.c',
))

arm_common_user_system_ss.add(
  m_nocp_d,
  mve_d,
  neon_d,
  translate32_d,
  vfp_d,
  files(
  'debug.c',
  'gengvec.c',
  'hflags.c',
  'm_helper.c',
  'mve_helper.c',
  'neon_helper.c',
  'op_helper.c',
  'translate.c',
  'translate-m-nocp.c',
  'translate-mve.c',
  'translate-neon.c',
  'translate-vfp.c',
  'vec_helper.c',
  'vfp_helper.c',
))
arm_common_user_system_ss.add(when: 'TARGET_AARCH64', if_true: files(
  'cpu64.c',
))

arm_common_system_ss.add(files(
  'cpregs-at.c',
  'gicv5-cpuif.c',
  'psci.c',
  'tlb_helper.c',
  'tlb-insns.c',
))
arm_common_system_ss.add(when: 'CONFIG_ARM_GICV5', if_true: files(
  'gicv5-cpuif.c',
))
arm_user_ss.add(files(
  'tlb_helper.c',
))
