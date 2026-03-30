project('igvm', 'c',
  version: '0.4.0',
  license: 'MIT',
)

cargo = find_program('cargo')

# Build the igvm Rust library as a C-compatible static library using cargo.
# The headers in igvm_c/include/ are pre-generated via cbindgen.
igvm_lib = custom_target('igvm_staticlib',
  output: 'libigvm.a',
  env: {'CARGO_TARGET_DIR': '@PRIVATE_DIR@' / 'cargo'},
  command: [
    'sh', '-c',
    '"$1" build --release --features igvm-c ' +
    '--manifest-path "$2"/igvm/Cargo.toml ' +
    '&& cp "$3"/cargo/release/libigvm.a "$4"',
    '--',
    cargo.full_path(),
    meson.current_source_dir(),
    '@PRIVATE_DIR@',
    '@OUTPUT0@',
  ],
  build_by_default: true,
)

# Wrapper headers in include/igvm/ redirect to igvm_c/include/ so that
# #include <igvm/igvm.h> works.
igvm_inc = include_directories('include')

igvm_dep = declare_dependency(
  link_with: igvm_lib,
  include_directories: igvm_inc,
)

meson.override_dependency('igvm', igvm_dep)
