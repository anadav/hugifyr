# ELF Hugepage Aligner (hugifyr)

This tool is designed to modify ELF (Executable and Linkable Format) files to align executable segments with huge pages. It's particularly useful for optimizing the memory layout of large executables or shared libraries.

## Features

- Aligns executable segments to 2MB huge pages
- Adjusts ELF headers, program headers, and section headers
- Updates symbol tables, dynamic sections, and relocations
- Handles compressed ELF sections
- Experimental support for adjusting debug information (DWARF)
- Updates build ID to maintain debug info compatibility

## Dependencies

This project requires the following libraries:

- libelf
- libdwarf
- zlib
- libzstd

### Installing Dependencies

#### Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install libelf-dev libdwarf-dev zlib1g-dev libzstd-dev
```

#### Fedora:

```bash
sudo dnf install elfutils-libelf-devel libdwarf-devel zlib-devel libzstd-devel
```

#### Arch Linux:

```bash
sudo pacman -S libelf libdwarf zlib zstd
```

Make sure these are installed on your system before compiling the tool.

## Building

To build the project, use the following commands:

```bash
./configure
make
sudo make install
```

This will install the `hugifyr` executable and the `hugifylibs.py` script.

## Usage

### Basic Usage

```
hugifyr [options] <input-elf> <output-elf>
```

#### Options:

- `-d`: Enable debug output
- `-n`: Do not adjust debug sections
- `-p`: Disable padding of the output file
- `-h`: Display detailed usage information

#### Example:

```bash
bin/hugifyr -d input.so output.so
```

This command will process `input.so`, align its executable segments to huge pages, and save the result as `output.so`, with debug output enabled.

### Using hugifylibs.py

The `hugifylibs.py` script is provided to ease the use of `hugifyr` with libraries and debug symbols. It can process multiple libraries at once and handle debug symbols separately.

```bash
python3 hugifylibs.py [options] <library1> [<library2> ...]
```

For detailed usage of `hugifylibs.py`, run:

```bash
python3 hugifylibs.py --help
```

### Utilizing Huge Pages

To actually benefit from the huge page alignment, you need to use the provided bash script or manually set up the environment. Here's how to use the bash script:

```bash
./run_with_preload.sh <path_to_executable> [args...]
```

This script sets up the necessary environment variables (`LD_PRELOAD` and `LD_LIBRARY_PATH`) to use the huge page-aligned libraries.

Alternatively, you can manually set these environment variables:

```bash
LD_PRELOAD=./bin/tcollapse.so LD_LIBRARY_PATH=/path/to/hugepage/aligned/libs your_executable [args...]
```

### File System Requirements

To benefit from huge pages, your file system must support folios. The following file systems are known to support this feature:

- XFS
- AFS
- Bcachefs
- EROFS
- NFS
- SMB (client)
- ZoneFS

If you're using one of these file systems, you're more likely to see performance improvements from huge page alignment.

### Transparent HugePages Configuration

Before using hugifyr, you need to ensure your system's Transparent HugePages (THP) settings are properly configured. Two key settings must be verified:

1. Enable Transparent HugePages:
```bash
# Check current setting
cat /sys/kernel/mm/transparent_hugepage/enabled

# Set it to 'madvise' or 'always' (requires root)
echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
```

2. Configure defragmentation settings:
```bash
# Check current setting
cat /sys/kernel/mm/transparent_hugepage/defrag

# Set it to 'madvise' or 'always' (requires root)
echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/defrag
```

To make these changes permanent across reboots, you can add the following to `/etc/rc.local` (create it if it doesn't exist):

```bash
#!/bin/bash

echo madvise > /sys/kernel/mm/transparent_hugepage/enabled
echo madvise > /sys/kernel/mm/transparent_hugepage/defrag

exit 0
```

Make sure to make the file executable:
```bash
sudo chmod +x /etc/rc.local
```

Alternatively, you can create a systemd service by creating `/etc/systemd/system/hugepage-settings.service`:

```ini
[Unit]
Description=Set Transparent Hugepage Settings
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'echo madvise > /sys/kernel/mm/transparent_hugepage/enabled && echo madvise > /sys/kernel/mm/transparent_hugepage/defrag'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:
```bash
sudo systemctl enable hugepage-settings
sudo systemctl start hugepage-settings
```

Note: While 'always' mode can potentially provide better performance, 'madvise' is generally recommended as it gives more control over which memory regions use huge pages. This can help prevent unnecessary memory usage in applications that don't benefit from huge pages.

### Debug Information Handling

The DWARF debug information handling in hugifyr is experimental. Bug reports are welcome! By default, hugifyr will attempt to update DWARF debug information. You can disable this with the `-n` option if you encounter issues.

If your system separates debug symbols into separate packages (common in many distributions), you'll need to merge the debug information before processing with hugifyr. Here's how:

1. Install the required tools:
   ```bash
   # On Debian/Ubuntu
   sudo apt-get install elfutils
   # On Fedora
   sudo dnf install elfutils
   ```

2. Merge the debug information:
   ```bash
   eu-unstrip -o merged_binary original_binary debug_file
   ```
   
   For example:
   ```bash
   eu-unstrip -o mylib.so.merged mylib.so /usr/lib/debug/.build-id/xx/yyyyyyyy.debug
   ```

3. Then process the merged file with hugifyr:
   ```bash
   hugifyr mylib.so.merged mylib.so.hugepage
   ```

The build ID of the processed file is automatically updated to maintain compatibility with debug tools and the debug information files.

## Notes

- This tool modifies ELF files in-place. Always make a backup of your original files before using this tool.
- The tool is designed for ELF files that are position-independent code (PIE) or shared libraries.
- Modifying ELF files can potentially break them if not done correctly. Use this tool with caution, especially on critical system files.
- When using `hugifylibs.py`, it will attempt to handle debug symbols automatically if they are available.
- Performance gains are dependent on both using the provided preload mechanism and having a compatible file system.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.