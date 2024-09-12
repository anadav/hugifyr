# Copyright (c) 2024 Nadav Amit
#
# SPDX-License-Identifier: MIT
import argparse
import os
import subprocess
import shutil
import tempfile
import sys

verbose:bool = False

def get_dependencies(executable, visited=None):
    if visited is None:
        visited = set()

    print(f"Getting dependencies for {executable}")
    
    if executable in visited:
        return []
    
    visited.add(executable)
    
    try:
        result = subprocess.run(['ldd', executable], capture_output=True, text=True, check=True)
        dependencies = [line.split()[2] for line in result.stdout.splitlines() if '=>' in line and line.split()[2] != 'not']
        
        all_dependencies = [executable]
        for dep in dependencies:
            all_dependencies.extend(get_dependencies(dep, visited))
        
        return list(dict.fromkeys(all_dependencies))  # Remove duplicates while preserving order
    except subprocess.CalledProcessError:
        print(f"Error: Unable to get dependencies for {executable}")
        return []

def get_segment_size(file_path):
    try:
        result = subprocess.run(['readelf', '-l', file_path], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if i == len(lines) - 1:
                break
            if 'LOAD' in line and 'R E' in lines[i + 1]:
                size_line = lines[i + 1].strip().split()
                if len(size_line) >= 2:
                    size = int(size_line[1], 16)
                    return size // (1024)  # Convert to KB
        print(f"Warning: No suitable LOAD segment found for {file_path}")
        return 0
    except subprocess.CalledProcessError:
        print(f"Error: Unable to get segment size for {file_path}")
        return 0

def get_build_id(file_path):
    try:
        result = subprocess.run(['readelf', '-n', file_path], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if 'Build ID:' in line:
                return line.split(':')[1].strip()
        return None
    except subprocess.CalledProcessError:
        print(f"Error: Unable to get Build ID for {file_path}")
        return None

def copy_permissions(src_path, dst_path):
    """Copy the permissions from source file to destination file."""
    st = os.stat(src_path)
    os.chmod(dst_path, st.st_mode)

def process_file(file_path, output_dir, size_threshold, processor, debug):
    global verbose
    output_path = os.path.join(output_dir, os.path.basename(file_path))
    if os.path.exists(output_path):
        print(f"Skipping {file_path} : already processed")
        return None
    
    size = get_segment_size(file_path)
    if size < size_threshold:
        print(f"Skipping {file_path} : size below threshold ({size} KB)")
        return None

    try:
        input_file = file_path
        
        if debug:
            build_id = get_build_id(file_path)
            if build_id:
                debug_file = f"/usr/lib/debug/.build-id/{build_id[:2]}/{build_id[2:]}.debug"
                if os.path.exists(debug_file):
                    with tempfile.NamedTemporaryFile(prefix="debug_", suffix=".tmp", delete=False) as tmp_file:
                        subprocess.run(['eu-unstrip', file_path, debug_file, '-o', tmp_file.name], check=True)
                        input_file = tmp_file.name
                        # Copy original file permissions to the temporary file
                        copy_permissions(file_path, tmp_file.name)
                else:
                    print(f"Debug file not found: {debug_file}")
            else:
                print(f"Build ID not found for {file_path}")
        
        #result = subprocess.run([processor, input_file, output_path], check=True)
        # Get the results, but output into a buffer
        result = subprocess.run([processor, input_file, output_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if verbose:
            print(result.stdout)
            print(result.stderr)
        result.check_returncode()
        
        # Copy original file permissions to the output file
        copy_permissions(file_path, output_path)

        if not debug and input_file != file_path:
            os.unlink(input_file)
        
        print(f"Processed {file_path} -> {output_path}")
        return True
    except subprocess.CalledProcessError:
        print(f"Error: Processing failed for {file_path}")
        return False
    except OSError as e:
        print(f"Error: Permission operation failed for {file_path}: {e}")
        return False
    finally:
        if debug and input_file != file_path:
            try:
                os.unlink(input_file)
            except OSError:
                pass

def check_required_tools():
    missing_tools = []

    # Check for eu-unstrip
    if not shutil.which('eu-unstrip'):
        missing_tools.append('eu-unstrip')

    # Check for ldd
    if not shutil.which('ldd'):
        missing_tools.append('ldd')

    if missing_tools:
        print("Error: The following required tools are not installed:")
        for tool in missing_tools:
            print(f"- {tool}")
        
        print("\nPlease install the missing tools and try again.")
        
        if 'eu-unstrip' in missing_tools:
            print("\nTo install eu-unstrip:")
            print("- On Ubuntu/Debian: sudo apt-get install elfutils")
            print("- On Fedora/CentOS: sudo dnf install elfutils")
            print("- On Arch Linux: sudo pacman -S elfutils")
        
        if 'ldd' in missing_tools:
            print("\nTo install ldd:")
            print("- On most Linux systems, ldd is part of the glibc package and should be installed by default.")
            print("- If it's missing, try updating your system: sudo apt update && sudo apt upgrade (for Ubuntu/Debian)")
        
        sys.exit(1)

    print("All required tools are installed.")

def main():
    global verbose
    parser = argparse.ArgumentParser(description="Process executable and its dependencies.")
    parser.add_argument("executable", help="Path to the executable")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--size-threshold", type=int, default=4, help="Size threshold in KB")
    parser.add_argument("--processor", default="bin/hugifyr", help="Path to the hugifyr")
    parser.add_argument("--debug", action="store_true", help="Use debug symbols if available")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if args.verbose:
        verbose = True

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    dependencies = get_dependencies(args.executable)
    
    succeeded = 0
    failed = 0
    skipped = 0

    for dep in dependencies:
        result = process_file(dep, args.output_dir, args.size_threshold, args.processor, args.debug)
        if result is True:
            succeeded += 1
        elif result is False:
            failed += 1
        else:
            skipped += 1

    print(f"Processing complete. Succeeded: {succeeded}, Failed: {failed}, Skipped: {skipped}")

if __name__ == "__main__":
    main()