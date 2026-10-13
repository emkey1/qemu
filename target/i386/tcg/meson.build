i386_ss.add(when: 'CONFIG_TCG', if_true: files(
  'access.c',
  'bpt_helper.c',
  'cc_helper.c',
  'excp_helper.c',
  'fpu_helper.c',
  'int_helper.c',
  'mem_helper.c',
  'misc_helper.c',
  'mpx_helper.c',
  'seg_helper.c',
  'string_helper.c',
  'tcg-cpu.c',
  'translate.c'), if_false: files('tcg-stub.c'))

# AOK gadgets: the x86-64 front end (system emulation, AArch64 hosts).
if get_option('aok_gadgets')
  i386_system_ss.add(when: 'TARGET_X86_64', if_true: files(
    'aok/gadgets.S',
    'aok/translate-x86.c',
  ))
endif

subdir('system')
subdir('user')
