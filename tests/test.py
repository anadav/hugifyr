#!/usr/bin/env python3
import subprocess
import sys
import re
import os

def run_command(cmd):
    """Run command and return output, raise exception on failure"""
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command {cmd} failed: {result.stderr}")
    return result.stdout

def check_segment_alignment(filename):
    """Check if executable segment is properly 2MB aligned"""
    ALIGN_SIZE = 0x200000  # 2MB
    output = run_command(['readelf', '-Wl', filename])
    
    # Parse readelf output looking for LOAD segments
    lines = output.splitlines()
    for i in range(len(lines)):
        if 'LOAD' in lines[i]:
            # Get the flags from next line
            if i + 1 < len(lines) and 'R E' in lines[i + 1]:
                # Found executable segment, parse values
                load_match = re.search(r'LOAD\s+(\w+)\s+(\w+)', lines[i])
                if not load_match:
                    raise RuntimeError(f"Failed to parse LOAD segment in {filename}")
                
                offset = int(load_match.group(1), 16)
                vaddr = int(load_match.group(2), 16)
                align_match = re.search(r'0x([0-9a-f]+)$', lines[i])
                if not align_match:
                    print(lines[i])
                    raise RuntimeError(f"Failed to parse alignment in {filename}")
                n_groups = len(align_match.groups())
                align = int(align_match.group(n_groups-1), 16)

                if align != ALIGN_SIZE:
                    raise RuntimeError(f"Alignment not 2MB in {filename}. Found: {align:#x}")
                if offset % ALIGN_SIZE != 0:
                    raise RuntimeError(f"Offset not 2MB aligned in {filename}. Found: {offset:#x}")
                if vaddr % ALIGN_SIZE != 0:
                    raise RuntimeError(f"Virtual address not 2MB aligned in {filename}. Found: {vaddr:#x}")
                print(f"Segment alignment OK in {filename}")
                return True
    
    raise RuntimeError(f"No executable segment found in {filename}")

def main():
    # Compile test program
    print("Compiling test program...")
    run_command(['gcc', '-g', '-fPIC', '-shared', 'test1.c', '-o', 'libtest1.so'])
    run_command(['gcc', '-g', '-pie', 'test1.c', '-o', 'test1.exe'])

    # Run original program
    print("Running original program...")
    original_output = run_command(['./test1.exe'])
    print(f"Original output: {original_output.strip()}")

    # Run hugifyr
    print("Running hugifyr...")
    run_command(['../bin/hugifyr', 'libtest1.so', 'libtest1_huge.so'])
    run_command(['../bin/hugifyr', 'test1.exe', 'test1_huge.exe'])

    # Make files executable
    os.chmod('test1_huge.exe', 0o755)
    os.chmod('libtest1_huge.so', 0o755)

    # Run modified program
    print("Running modified program...")
    modified_output = run_command(['./test1_huge.exe'])
    print(f"Modified output: {modified_output.strip()}")

    # Compare outputs
    if original_output != modified_output:
        raise RuntimeError("Output mismatch!")

    # Check segment alignments
    check_segment_alignment('test1_huge.exe')
    check_segment_alignment('libtest1_huge.so')

    # Check debug info
    print("Checking debug info...")
    gdb_output = run_command(['gdb', '-batch', '-ex', 'file test1_huge.exe', 
                            '-ex', 'br calculate', '-ex', 'run'])
    if 'Breakpoint 1 at' not in gdb_output:
        raise RuntimeError("Debug info verification failed")

    print("All tests passed!")
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Test failed: {e}", file=sys.stderr)
        sys.exit(1)