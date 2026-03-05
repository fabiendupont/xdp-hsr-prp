# SPDX-License-Identifier: BSD-2-Clause

project('xdp-hsr-prp', 'c',
    version: '0.1.0',
    license: 'BSD-2-Clause',
    meson_version: '>=0.56.0',
    default_options: [
        'c_std=c11',
        'warning_level=3',
        'buildtype=debug',
        'werror=true',
    ])

cc = meson.get_compiler('c')
extra_c_args = cc.get_supported_arguments(
    '-Wconversion',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wmissing-prototypes',
)

# --- Dependencies ---

# xdp-graph-lib transitively brings ebpf-graph-lib
xgl_dep = dependency('xdp-graph-lib',
    fallback: ['xdp-graph-lib', 'xgl_dep'],
    required: true)

egl_dep = dependency('ebpf-graph-lib',
    fallback: ['ebpf-graph-lib', 'egl_dep'],
    required: true)

libbpf_dep = dependency('libbpf', version: '>=1.0')
libelf_dep = dependency('libelf')
thread_dep = dependency('threads')

# --- Include directories ---

inc = include_directories('include')

# --- BPF programs ---

clang = find_program('clang')

# Gather include paths from dependencies for BPF compilation
xgl_inc = meson.current_source_dir() / 'subprojects' / 'xdp-graph-lib' / 'include'
egl_inc = meson.current_source_dir() / 'subprojects' / 'ebpf-graph-lib' / 'include'

bpf_cflags = [
    '-target', 'bpf',
    '-O2', '-g',
    '-Wall', '-Wextra',
    '-D__TARGET_ARCH_x86',
    '-D__BPF__',
    '-I' + meson.current_source_dir() / 'include',
    '-I' + meson.current_source_dir() / 'src' / 'bpf',
    '-I' + xgl_inc,
    '-I' + egl_inc,
]

# XDP ingress nodes
xdp_nodes = ['node_hsr_ingress', 'node_hsr_forward', 'node_prp_ingress']

# TC egress programs
tc_nodes = ['node_hsr_egress', 'node_prp_egress']

bpf_targets = []
foreach node : xdp_nodes + tc_nodes
    bpf_targets += custom_target(node + '.bpf.o',
        input: 'src' / 'bpf' / node + '.bpf.c',
        output: node + '.bpf.o',
        command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
        install: true,
        install_dir: get_option('libdir') / 'bpf')
endforeach

# --- Userspace library ---

hsr_prp_lib = static_library('hsr_prp',
    'src/userspace/hsr_prp_config.c',
    'src/userspace/hsr_prp_nodetable.c',
    'src/userspace/hsr_prp_supervision.c',
    'src/userspace/hsr_prp_stats.c',
    include_directories: inc,
    dependencies: [xgl_dep, libbpf_dep, libelf_dep, thread_dep],
    c_args: extra_c_args)

hsr_prp_dep = declare_dependency(
    link_with: hsr_prp_lib,
    include_directories: inc,
    dependencies: [xgl_dep, libbpf_dep])

# --- Unit tests ---

test_seq_after = executable('test_seq_after',
    'tests/unit/test_seq_after.c',
    include_directories: [inc, include_directories('src/bpf')],
    c_args: extra_c_args)

test_hsr_tag = executable('test_hsr_tag',
    'tests/unit/test_hsr_tag.c',
    include_directories: inc,
    c_args: extra_c_args)

test_prp_rct = executable('test_prp_rct',
    'tests/unit/test_prp_rct.c',
    include_directories: inc,
    c_args: extra_c_args)

test('seq_after', test_seq_after, suite: 'unit')
test('hsr_tag', test_hsr_tag, suite: 'unit')
test('prp_rct', test_prp_rct, suite: 'unit')

# --- CBMC verification ---

cbmc = find_program('cbmc', required: false)

if cbmc.found()
    test('cbmc_seq_after', cbmc,
        args: ['--unwind', '1', '--unwinding-assertions',
               meson.current_source_dir() / 'verification' / 'cbmc' /
               'seq_after_harness.c'],
        suite: 'cbmc',
        timeout: 300)

    test('cbmc_hsr_tag_parse', cbmc,
        args: ['--unwind', '7', '--unwinding-assertions',
               meson.current_source_dir() / 'verification' / 'cbmc' /
               'hsr_tag_parse_harness.c'],
        suite: 'cbmc',
        timeout: 300)

    test('cbmc_prp_rct_strip', cbmc,
        args: ['--unwind', '7', '--unwinding-assertions',
               meson.current_source_dir() / 'verification' / 'cbmc' /
               'prp_rct_strip_harness.c'],
        suite: 'cbmc',
        timeout: 300)
endif

# --- Frama-C deductive verification ---

framac = find_program('frama-c', required: false)
framac_dir = meson.current_source_dir() / 'verification' / 'framac'

if framac.found()
    test('framac_seq_after', framac,
        args: ['-wp', '-wp-rte',
               framac_dir / 'seq_after_spec.c'],
        suite: 'framac',
        timeout: 120)

    test('framac_hsr_tag', framac,
        args: ['-wp', '-wp-rte',
               framac_dir / 'hsr_tag_spec.c'],
        suite: 'framac',
        timeout: 120)
endif

# --- TLA+ verification ---

tlc = find_program('tlc', required: false)
tla_dir = meson.current_source_dir() / 'verification' / 'tlaplus'

if tlc.found()
    test('tlaplus_hsr', tlc,
        args: ['-deadlock', tla_dir / 'HSRDupDiscard.tla',
               '-config', tla_dir / 'HSRDupDiscard.cfg'],
        suite: 'tlaplus',
        timeout: 600)

    test('tlaplus_prp', tlc,
        args: ['-deadlock', tla_dir / 'PRPDupDiscard.tla',
               '-config', tla_dir / 'PRPDupDiscard.cfg'],
        suite: 'tlaplus',
        timeout: 600)
endif

# --- Integration tests ---

test('hsr_ring', find_program(
         meson.current_source_dir() / 'tests' / 'integration' /
         'test_hsr_ring.sh'),
    suite: 'integration',
    is_parallel: false,
    timeout: 120)

# Privileged C integration test — loads BPF programs, sends real frames
test_hsr_datapath = executable('test_hsr_datapath',
    'tests/integration/test_hsr_datapath.c',
    include_directories: inc,
    link_with: hsr_prp_lib,
    dependencies: [xgl_dep, libbpf_dep, libelf_dep, thread_dep],
    c_args: extra_c_args + [
        '-DBPF_OBJ_DIR="' + meson.current_build_dir() + '"',
        '-Wno-missing-prototypes',
    ])

test('hsr_datapath', test_hsr_datapath,
    suite: 'integration',
    is_parallel: false,
    timeout: 120)

# --- Install headers ---

install_headers(
    'include/hsr_prp/hsr_tag.h',
    'include/hsr_prp/prp_rct.h',
    'include/hsr_prp/hsr_prp_common.h',
    'include/hsr_prp/hsr_prp_node_ids.h',
    'include/hsr_prp/hsr_prp_userspace.h',
    subdir: 'hsr_prp')

# --- Summary ---

summary({
    'Mode': get_option('buildtype'),
    'XDP nodes': xdp_nodes,
    'TC programs': tc_nodes,
    'CBMC available': cbmc.found(),
    'TLC available': tlc.found(),
}, section: 'Configuration')

message('Minimum kernel version: 5.1 (bpf_spin_lock)')
