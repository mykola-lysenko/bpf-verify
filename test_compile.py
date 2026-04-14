#!/usr/bin/env python3.11
"""Test compilation of specific targets to diagnose errors."""
import subprocess, sys
sys.path.insert(0, '/home/ubuntu/bpf-verify')

# Read pipeline constants by executing the top of pipeline.py
pipeline_src = open('/home/ubuntu/bpf-verify/pipeline.py').read()
# Execute just the constant definitions
exec_globals = {}
# Find the end of constants (before first function def)
setup_code = pipeline_src.split('\ndef compile_harness')[0]
exec(setup_code, exec_globals)

CLANG = exec_globals['CLANG']
BASE_CFLAGS = exec_globals['BPF_CFLAGS']
KSRC = exec_globals['KSRC']

def test_compile(src_path, name):
    cmd = [CLANG, '-target', 'bpf', '-O2', '-g'] + BASE_CFLAGS + ['-c', str(src_path), '-o', f'/tmp/{name}_test.o']
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"\n=== {name} (rc={result.returncode}) ===")
    if result.returncode != 0:
        # Show first 20 error lines
        errors = [l for l in result.stderr.split('\n') if 'error:' in l][:20]
        for e in errors:
            print(e)
    else:
        print("  SUCCESS")

test_compile(KSRC / 'lib/string.c', 'string')
test_compile(KSRC / 'lib/checksum.c', 'checksum')
test_compile(KSRC / 'lib/mpi/mpi-add.c', 'mpi_add')
