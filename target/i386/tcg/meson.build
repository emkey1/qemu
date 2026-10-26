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

# RCG's alternate structure for 64-bit code: the translator and the stream
# harness's gadgets, which rcg-gen.py writes, a few files of them so that the
# compile parallelises. The list must match its STREAM_FILES.
if get_option('tcg_threaded_interpreter') or get_option('tcg_hybrid') != 'disabled'
  rcg_stream_outputs = ['rcg_stream_gadgets.h', 'rcg_stream_gadgets.c']
  foreach f : ['alu_add', 'alu_sub', 'alu_and', 'alu_or', 'alu_xor',
               'alu_cmp', 'alu_test', 'mov', 'extend', 'unary', 'shift',
               'misc', 'cond']
    rcg_stream_outputs += 'rcg_stream_@0@.c'.format(f)
  endforeach
  rcg_stream_gadgets = custom_target('rcg-stream-gadgets',
    output: rcg_stream_outputs,
    input: files('rcg-gen.py'),
    depend_files: files(
      meson.project_source_root() / 'tcg' / 'aarch64-tcti' / 'tcti_memory.py',
      meson.project_source_root() / 'tests' / 'tcg' / 'x86_64' / 'system' / 'rcg-test.h'),
    command: [python, '@INPUT@', '--stream-gadgets', '@OUTDIR@'])
  i386_system_ss.add(when: 'TARGET_X86_64', if_true: [
    rcg_stream_gadgets, files('rcg-stream-translate.c')])
endif

subdir('system')
subdir('user')
