// Copyright (c) 2024 Nadav Amit
//
// SPDX-License-Identifier: MIT

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>
#include <dwarf.h>
#include <zlib.h>
#include <zstd.h>
#include <libdwarf.h>
#include <getopt.h>
#include "uthash.h"

#define PAGE_SIZE (4096)
#define HUGE_PAGE_SIZE (2 * 1024 * 1024)  // 2MB
#define SMALL_PAGE_LIMIT (4)
#define TEMP_SHDR_OFFSET_DELTA (8 * 1024 * 1024)

static bool debug = false;

#define pr_debug(fmt, ...) do { if (debug) fprintf(stdout, fmt, ##__VA_ARGS__); } while (0)
#define pr_error(fmt, ...) do { fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#define pr_info(fmt, ...) do { fprintf(stdout, fmt, ##__VA_ARGS__); } while (0)

#define NT_STAPSDT 3

#define FLAG_DEBUG_UPDATE           (1 << 0)
#define FLAG_FILE_PADDING           (1 << 1)

struct section_type_name_tuple {
    Elf64_Word type;
    const char *name;
};

// Array of section types using libelf constants
const struct section_type_name_tuple relocatable_section_types[] = {
    {SHT_NULL, NULL},
    {SHT_NOTE, NULL},
    {SHT_HASH, NULL},
    {SHT_GNU_HASH, NULL},
    {SHT_DYNSYM, NULL},
    {SHT_STRTAB, NULL},
    {SHT_GNU_versym, NULL},
    {SHT_GNU_verdef, NULL},
    {SHT_GNU_verneed, NULL},
    {SHT_RELA, NULL},
    {SHT_RELR, NULL},
    {SHT_DYNAMIC, NULL},
    {SHT_PROGBITS, ".interp"}
};

#define DW_SECT_ARANGES     (DW_SECT_RNGLISTS + 1) 
#define DW_SECT_NUM         (DW_SECT_ARANGES + 1)

#define DW_SECT_EH_FRAME 2

const char *debug_section_names[] = {
    [DW_SECT_INFO] = ".debug_info",
    /* [2] is reserved, we would abuse it for eh_frame */
    [DW_SECT_EH_FRAME] = ".eh_frame",
    [DW_SECT_ABBREV] = ".debug_abbrev",
    [DW_SECT_LINE] = ".debug_line",
    [DW_SECT_LOCLISTS] = ".debug_loclists",
    [DW_SECT_STR_OFFSETS] = ".debug_str_offsets",
    [DW_SECT_MACRO] = ".debug_macro",
    [DW_SECT_RNGLISTS] = ".debug_rnglists",
    [DW_SECT_ARANGES] = ".debug_aranges",
};

#define DW_EH_PE_absptr 0x00

struct elf_section {
    Elf_Scn *scn;
    GElf_Shdr shdr;
    //void *raw_data;     // merged
    //size_t raw_size;
    void *data;         // uncompressed
    size_t size;
    Elf_Data **_data;
    size_t _data_count;
    const char *name;
    bool is_dirty;
};

typedef struct {
    Dwarf_Off offset;
    UT_hash_handle hh;
} offset_entry;

typedef struct {
    const char *filename;
    int fd;
    Elf *elf;
    GElf_Ehdr ehdr;
    GElf_Phdr *phdrs;
    size_t phnum;
    Dwarf_Debug dbg;
    Dwarf_Half dwarf_offset_size;
    size_t shnum;
    ssize_t exec_index;
    ssize_t first_load_index;
    ssize_t *first_section_per_segment;
    struct elf_section *debug_sections[DW_SECT_NUM];
    struct elf_section *sections;
    struct elf_section **sections_ordered_by_offset;
    offset_entry *loclist_offsets;
} ElfInfo;

typedef struct {
    GElf_Addr old_exec_vaddr;
    GElf_Addr vaddr_delta;
    GElf_Off old_exec_offset;
    GElf_Off segment_offset_delta;
    GElf_Off section_offset_delta;
    bool adjust_offsets;
    bool sections_adjusted;
    bool adjust_debug;
} AdjInfo;

#define array_size(arr) (sizeof(arr) / sizeof(arr[0]))

static int get_section_data_uncached(struct elf_section *sec);

static bool is_section_compressed(const struct elf_section *sec) {
    return sec->shdr.sh_flags & SHF_COMPRESSED;
}

static bool is_section_no_data(const struct elf_section *sec) {
    return sec->shdr.sh_type == SHT_NOBITS || sec->shdr.sh_type == SHT_NULL;
}

static void mark_section_data_dirty(struct elf_section *sec) {
    for (size_t i = 0; i < sec->_data_count; i++) {
        if (elf_flagdata(sec->_data[i], ELF_C_SET, ELF_F_DIRTY) == 0) {
            pr_error("elf_flagdata() failed: %s\n", elf_errmsg(-1));
            exit(EXIT_FAILURE);
        }
    }
}

static void mark_section_dirty(struct elf_section *sec) {
    if (is_section_no_data(sec)) {
        return;
    }

    if (sec->data) {
        sec->is_dirty = true;
        return;
    }

    mark_section_data_dirty(sec);
}

static int update_section_data(ElfInfo *elf_info, struct elf_section *sec);

static void invalidate_section_data_cache(ElfInfo *elf_info, struct elf_section *sec) {
    if (sec->is_dirty && is_section_compressed(sec)) {
        update_section_data(elf_info, sec);
        free(sec->data);
        sec->data = NULL;
        sec->size = 0;
    }
}

void add_offset(offset_entry **offsets, Dwarf_Off new_offset) {
    offset_entry *entry;

    // Check if the offset already exists in the hash table
    HASH_FIND(hh, *offsets, &new_offset, sizeof(Dwarf_Off), entry);
    if (entry == NULL) {
        // If it doesn't exist, allocate memory and add the new offset
        entry = (offset_entry *)malloc(sizeof(offset_entry));
        if (entry == NULL) {
            pr_error("Memory allocation failed\n");
            exit(1);
        }
        entry->offset = new_offset;
        HASH_ADD(hh, *offsets, offset, sizeof(Dwarf_Off), entry);
    }
}

void free_offsets(offset_entry *offsets) {
    offset_entry *current_entry, *tmp;

    HASH_ITER(hh, offsets, current_entry, tmp) {
        HASH_DEL(offsets, current_entry);
        free(current_entry);
    }
}

static uint64_t round_down(uint64_t value, uint64_t alignment) {
    if (alignment == 0) {
        return value;
    }
    return (value / alignment) * alignment;
}

static uint64_t round_up(uint64_t value, uint64_t alignment) {
    if (alignment == 0) {
        return value;
    }
    return ((value + alignment - 1) / alignment) * alignment;
}

static uint64_t round_up_delta(uint64_t value, uint64_t alignment) {
    return round_up(value, alignment) - value;
}

static void buf_consume(void **p, size_t size, void *end)
{
    assert(*p + size <= end && "Buffer overflow");
    *p += size;
}

static uint64_t __buf_uread(void **p, uint8_t size, void *end, bool advance)
{
    uint64_t value;
    assert(*p + size <= end && "Buffer overflow");
    switch (size) {
    case 1:
        value = *(uint8_t *)*p;
        break;
    case 2:
        value = *(uint16_t *)*p;
        break;
    case 4:
        value = *(uint32_t *)*p;
        break;
    case 8:
        value = *(uint64_t *)*p;
        break;
    default:
        assert(0 && "Invalid size");
    }
    if (advance) {
        *p += size;
    }
    return value;
}

static uint64_t buf_uread(void **p, uint8_t size, void *end) {
    return __buf_uread(p, size, end, true);
}

static void buf_consume_block_fixed(void **p, uint8_t block_size_bytes, void *end)
{
    size_t size = buf_uread(p, block_size_bytes, end);
    buf_consume(p, size, end);
}

static void buf_align_offset(void **p, uint8_t alignment, void *start, void *end)
{
    buf_consume(p, round_up_delta(*p - start, alignment), end);
}

static uint64_t buf_uleb128_decode(void **p, void *end) {
    uint64_t result = 0;
    uint8_t shift = 0;
    size_t bytes_read = 0;

    while (1) {
        uint8_t byte = buf_uread(p, 1, end);
        bytes_read++;

        result |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }

    assert(shift < 64);  // Ensure we don't have an overflow
    assert(bytes_read <= 10);  // ULEB128 values should not be longer than 10 bytes

    return result;
}

static void buf_consume_block_uleb128(void **p, void *end)
{
    uint64_t size = buf_uleb128_decode(p, end);
    buf_consume(p, size, end);
}

static int64_t buf_sread(void **p, uint8_t size, void *end)
{
    int64_t value;
    assert(*p + size <= end && "Buffer overflow");
    switch (size) {
    case 1:
        value = *(int8_t *)*p;
        break;
    case 2:
        value = *(int16_t *)*p;
        break;
    case 4:
        value = *(int32_t *)*p;
        break;
    case 8:
        value = *(int64_t *)*p;
        break;
    default:
        assert(0 && "Invalid size");
    }
    *p += size;
    return value;
}

static void write_address(void *p, uint64_t value, uint8_t address_size) {
    if (address_size == 8) {
        *(uint64_t *)p = value;
        return;
    }
    assert(address_size == 4);
    *(uint32_t *)p = value;
}

static GElf_Addr calc_adjusted_addr(AdjInfo *adj_info, GElf_Addr addr)
{
    if (addr >= adj_info->old_exec_vaddr) {
        return addr + adj_info->vaddr_delta;
    }
    return addr;
}

// Return 1 if updated, 0 if not
static int buf_update_addr(AdjInfo *adj_info, void **p, uint8_t size,
                           void *end, const char *update_msg) {
    void *p_addr = *p;
    uint64_t old_addr = buf_uread(p, size, end);
    uint64_t new_addr = calc_adjusted_addr(adj_info, old_addr);

    if (old_addr == new_addr){
        return 0;
    }

    pr_debug("Updating: 0x%lx -> 0x%lx (%s)\n", old_addr, new_addr, update_msg);
    write_address(p_addr, new_addr, size);
    return 1;
}

static int binary_copy(const char *src_filename, const char *dst_filename) {
    int r = -1;
    int src_fd = -1;
    int dst_fd = -1;
    char *buf = NULL;

    src_fd = open(src_filename, O_RDONLY);
    if (src_fd == -1) {
        perror("open");
        goto out;
    }

    struct stat src_stat;
    if (fstat(src_fd, &src_stat) == -1) {
        perror("fstat");
        goto out;
    }

    dst_fd = open(dst_filename, O_WRONLY | O_CREAT | O_TRUNC, src_stat.st_mode & 0777);
    if (dst_fd == -1) {
        perror("open");
        goto out;
    }

    buf = malloc(4096);
    if (!buf) {
        perror("malloc");
        goto out;
    }

    ssize_t nread;
    while ((nread = read(src_fd, buf, 4096)) > 0) {
        if (write(dst_fd, buf, nread) != nread) {
            perror("write");
            goto out;
        }
    }

    if (nread == -1) {
        perror("read");
        goto out;
    }

    r = 0;

out:
    if (buf) {
        free(buf);
    }
    if (src_fd != -1) {
        close(src_fd);
    }
    if (dst_fd != -1) {
        close(dst_fd);
    }
    return r;
}

static struct elf_section *find_section_by_name(ElfInfo *elf_info, const char *search_name) {
    for (size_t i = 0; i < elf_info->shnum; ++i) {
        if (strcmp(elf_info->sections[i].name, search_name) == 0) {
            return &elf_info->sections[i];
        }
    }
    return NULL;
}

// Function to compare two sections based on their file offset
static int compare_sections(const void *a, const void *b) {
    struct elf_section *sec_a = *(struct elf_section **)a;
    struct elf_section *sec_b = *(struct elf_section **)b;

    return (sec_a->shdr.sh_offset > sec_b->shdr.sh_offset) -
            (sec_a->shdr.sh_offset < sec_b->shdr.sh_offset);
}

static int update_elf_offsets(ElfInfo *elf_info, struct elf_section *sec, size_t new_size) {
    GElf_Shdr *target_shdr = &sec->shdr;

    size_t old_end_offset = target_shdr->sh_offset + target_shdr->sh_size;
    size_t new_end_offset = target_shdr->sh_offset + new_size; 
    ssize_t delta = new_end_offset - old_end_offset;

    if (delta <= 0) {
        target_shdr->sh_size = new_size;
        return 0;
    }
    
    for (size_t i = 0; i < elf_info->shnum; i++) {
        struct elf_section *sec = &elf_info->sections[i];

        if (sec->shdr.sh_offset < old_end_offset)
            continue;

        // We cannot manage "allocated" sections
        assert(!(sec->shdr.sh_flags & SHF_ALLOC) && "Cannot manage allocated sections");

        size_t new_offset = sec->shdr.sh_offset + delta;
        size_t new_aligned_offset = round_up(new_offset, sec->shdr.sh_addralign);

        delta += new_aligned_offset - new_offset;

        sec->shdr.sh_offset += delta;
        // Ensure alignment is correct
        assert(sec->shdr.sh_offset % sec->shdr.sh_addralign == 0);
        mark_section_dirty(sec);
    }

    size_t align = (elf_info->ehdr.e_ident[EI_CLASS] == ELFCLASS64) ? 8 : 4;

    // XXX: for now we assume the section is the last one
    if (elf_info->ehdr.e_shoff > old_end_offset) {
        elf_info->ehdr.e_shoff = round_up(elf_info->ehdr.e_shoff + delta, align);
    }

    if (elf_info->ehdr.e_phoff > old_end_offset) {
        elf_info->ehdr.e_shoff = round_up(elf_info->ehdr.e_phoff + delta, align);
    }

    target_shdr->sh_size = new_size;
    return 0;
}

static int64_t sleb128_decode(const unsigned char **buf) {
    int64_t result = 0;
    uint8_t shift = 0;
    size_t bytes_read = 0;
    uint8_t byte;

    do {
        byte = **buf;
        (*buf)++;
        bytes_read++;
        result |= ((int64_t)(byte & 0x7f)) << shift;
        shift += 7;
    } while (byte & 0x80);

    if ((shift < 64) && (byte & 0x40)) {
        result |= -(1LL << shift);
    }

    assert(shift < 64);  // Ensure we don't have an overflow
    assert(bytes_read <= 10);  // SLEB128 values should not be longer than 10 bytes

    return result;
}

static size_t buf_consume_string(void **p, void *end) {
    size_t len = strlen(*(const char **)p) + 1;
    buf_consume(p, len, end);
    return len - 1;
}

static void skip_form_content(uint64_t form, void **p, uint8_t addr_size,
                              uint8_t offset_size, void *end) {
    switch (form) {
        case DW_FORM_addr:
            buf_uread(p, addr_size, end);
            break;
        case DW_FORM_block2:
            buf_consume_block_fixed(p, 2, end);
            break;
        case DW_FORM_block4:
            buf_consume_block_fixed(p, 4, end);
            break;
        case DW_FORM_data2:
        case DW_FORM_ref2:
            buf_consume(p, 2, end);
            break;
        case DW_FORM_data4:
        case DW_FORM_ref4:
        case DW_FORM_strp:
        case DW_FORM_line_strp:
        case DW_FORM_ref_sup4:
        case DW_FORM_strp_sup:
            buf_consume(p, 4, end);
            break;
        case DW_FORM_data8:
        case DW_FORM_ref8:
        case DW_FORM_ref_sig8:
        case DW_FORM_ref_sup8:
            buf_consume(p, 8, end);
            break;
        case DW_FORM_data16:
            buf_consume(p, 16, end);
            break;
        case DW_FORM_string:
            buf_consume_string(p, end);
            break;
        case DW_FORM_block:
        case DW_FORM_exprloc:
            buf_consume_block_uleb128(p, end);
            break;
        case DW_FORM_block1:
            buf_consume_block_fixed(p, 1, end);
            break;
        case DW_FORM_data1:
        case DW_FORM_ref1:
        case DW_FORM_flag:
            buf_consume(p, 1, end);
            break;
        case DW_FORM_sdata:
        case DW_FORM_udata:
        case DW_FORM_ref_udata:
        case DW_FORM_strx:
        case DW_FORM_addrx:
        case DW_FORM_loclistx:
        case DW_FORM_rnglistx:
            buf_uleb128_decode(p, end);
            break;
        case DW_FORM_ref_addr:
            buf_consume(p, offset_size, end);
            break;
        case DW_FORM_indirect: {
            uint64_t value = buf_uleb128_decode(p, end);
            skip_form_content(value, p, addr_size, offset_size, end);  // Recursive call for the actual form
            break;
        }
        case DW_FORM_sec_offset:
            buf_consume(p, offset_size, end);
            break;
        case DW_FORM_flag_present:
        case DW_FORM_implicit_const:
            // No data to skip
            break;
        case DW_FORM_strx1:
        case DW_FORM_addrx1:
            buf_consume(p, 1, end);
            break;
        case DW_FORM_strx2:
        case DW_FORM_addrx2:
            buf_consume(p, 2, end);
            break;
        case DW_FORM_strx3:
        case DW_FORM_addrx3:
            buf_consume(p, 3, end);
            break;
        case DW_FORM_strx4:
        case DW_FORM_addrx4:
            buf_consume(p, 4, end);
            break;
        case DW_FORM_GNU_addr_index:
        case DW_FORM_GNU_str_index:
            buf_uleb128_decode(p, end);
            break;
        case DW_FORM_GNU_ref_alt:
        case DW_FORM_GNU_strp_alt:
            buf_consume(p, offset_size, end);
            break;
        default:
            pr_error("Unhandled DW_FORM: 0x%lx\n", form);
            assert(0);  // Unhandled form
    }
}

static int get_section_data(struct elf_section *sec) {
    void *uncompressed_buf = NULL;

    // If we already read the section data, return it
    if (sec->data) {
        return 0;
    }

    if (is_section_no_data(sec)) {
        // No data to read
        sec->data = NULL;
        sec->size = 0;
        return 0;
    }

    assert(sec->_data_count <= 1 && "Multiple data entries in section are unsupported");
    if (is_section_compressed(sec)) {
        // ELFCLASS64
        Elf64_Chdr *chdr = (Elf64_Chdr *)sec->_data[0]->d_buf;
        const void *compressed_data =  chdr + 1;
        size_t compressed_size = sec->_data[0]->d_size - sizeof(Elf64_Chdr);

        unsigned long uncompressed_size = chdr->ch_size;
        uncompressed_buf = malloc(uncompressed_size);

        switch (chdr->ch_type) {
            case ELFCOMPRESS_ZLIB:
                if (uncompress(uncompressed_buf, &uncompressed_size, compressed_data, compressed_size) != Z_OK) {
                    pr_error("Failed to decompress %s section\n", sec->name);
                    goto do_err;
                }
                break;
            case ELFCOMPRESS_ZSTD:
                if (ZSTD_decompress(uncompressed_buf, uncompressed_size, compressed_data, compressed_size) != uncompressed_size) {
                    pr_error("Failed to decompress %s section\n", sec->name);
                    goto do_err;
                }
                break;
            default:
                pr_error("Unsupported compression type\n");
                goto do_err;
        }
        
        sec->data = uncompressed_buf;
        sec->size = uncompressed_size;
    } else {
        sec->data = sec->_data[0]->d_buf;
        sec->size = sec->_data[0]->d_size;
    }

    return 0;
do_err:
    free(uncompressed_buf);
    return -1;
}

static struct elf_section *get_section(ElfInfo *info, const char *name) {
    struct elf_section *sec = find_section_by_name(info, name);
    if (!sec) {
        pr_debug("Section %s not found\n", name);
        return NULL;
    }
    
    if (get_section_data(sec) < 0) {
        pr_error("Failed to get section data\n");
        return NULL;
    }

    return sec;
}

static struct elf_section *get_debug_section(ElfInfo *elf_info, uint8_t scn_id) {
    assert(scn_id <= array_size(debug_section_names) && "invalid debug section id");

    struct elf_section **c = &elf_info->debug_sections[scn_id];

    if (*c == NULL) {
        *c = get_section(elf_info, debug_section_names[scn_id]);
    }
    return *c;
}

static ssize_t update_attribute_offsets(ElfInfo *elf_info, AdjInfo *adj_info,
                                        Dwarf_Die cu_die, Dwarf_Die die,
                                        Dwarf_Half address_size, Dwarf_Half offset_size) {
    size_t n_updated = 0;
    Dwarf_Debug dbg = elf_info->dbg; 
    Dwarf_Error error = NULL;
    Dwarf_Off die_offset;
    Dwarf_Signed attr_count;
    Dwarf_Attribute *attrs = NULL;
    int r = -1;

    switch (dwarf_attrlist(die, &attrs, &attr_count, &error)) {
        case DW_DLV_ERROR:
            pr_error("Error getting attribute list: %s\n", dwarf_errmsg(error));
            goto out;
        case DW_DLV_NO_ENTRY:
            // No attributes to update
            return 0;
    }

    if (dwarf_dieoffset(die, &die_offset, &error) != DW_DLV_OK) {
        pr_error("Error getting DIE offset: %s\n", dwarf_errmsg(error));
        goto out;
    }

    // Get .debug_info section data
    struct elf_section *sec = get_debug_section(elf_info, DW_SECT_INFO);
    if (sec == NULL) {
        pr_debug("No .debug_info section\n");
        goto out;
    }

    void *end = sec->data + sec->size;
    void *current_pos = sec->data + die_offset;

    buf_uleb128_decode(&current_pos, end);  // Skip abbreviation code

    for (int i = 0; i < attr_count; i++) {
        // Get attribute tag
        Dwarf_Half attr_tag;
        if (dwarf_whatattr(attrs[i], &attr_tag, &error) != DW_DLV_OK) {
            pr_error("Error getting attribute tag: %s\n", dwarf_errmsg(error));
            goto out;
        }
        Dwarf_Half attr_form;
        if (dwarf_whatform(attrs[i], &attr_form, &error) != DW_DLV_OK) {
            pr_error("Error getting attribute form: %s\n", dwarf_errmsg(error));
            goto out;
        }
        
        Dwarf_Off addrx = 0;
        void *attr_pos = current_pos;
        switch (attr_form) {
            case DW_FORM_addr:
            {
                // Sanity check to see we parsed correctly.
                Dwarf_Addr dwarf_addr;
                if (dwarf_formaddr(attrs[i], &dwarf_addr, &error) != DW_DLV_OK) {
                    pr_error("Error getting address: %s\n", dwarf_errmsg(error));
                    goto out;
                }
                uint64_t elf_addr = __buf_uread(&attr_pos, address_size, end, false);
                assert(elf_addr == dwarf_addr);

                n_updated += buf_update_addr(adj_info, &attr_pos, address_size, end, "DW_FORM_addr");
                break;
            }
            case DW_FORM_sec_offset:
            {
                // Sanity check to see we parsed correctly.
                Dwarf_Off dwarf_offset;
                if (dwarf_global_formref(attrs[i], &dwarf_offset, &error) != DW_DLV_OK) {
                    pr_error("Error getting section offset: %s\n", dwarf_errmsg(error));
                    goto out;
                }
                uint64_t elf_offset = __buf_uread(&attr_pos, offset_size, end, false);
                assert(elf_offset == dwarf_offset);

                //n_updated += buf_update_addr(adj_info, &attr_pos, offset_size, end, "DW_FORM_sec_offset");
                if (attr_tag == DW_AT_stmt_list || attr_tag == DW_AT_ranges) {} else 
                if (attr_tag == DW_AT_location) { // || attr_tag == DW_AT_GNU_locviews) {
                    add_offset(&elf_info->loclist_offsets, elf_offset);
                }
                break;
            }
            case DW_FORM_addrx:
                addrx = buf_uleb128_decode(&attr_pos, end);
                break;
            case DW_FORM_addrx1:
                addrx = buf_uread(&attr_pos, 1, end);
                break;
            case DW_FORM_addrx2:
                addrx = buf_uread(&attr_pos, 2, end);
                break;
            case DW_FORM_addrx3:
                addrx = buf_uread(&attr_pos, 3, end);
                break;
            case DW_FORM_addrx4:
                addrx = buf_uread(&attr_pos, 4, end);
                break;
            case DW_FORM_loclistx:
            {
                Dwarf_Unsigned index, offset, global_offset;
                Dwarf_Off cu_die_offset;
                
                if (dwarf_formudata(attrs[i], &index, &error) != DW_DLV_OK) {
                    pr_error("Error getting loclistx index: %s\n", dwarf_errmsg(error));
                    goto out;
                }

                if (dwarf_dieoffset(cu_die, &cu_die_offset, &error) != DW_DLV_OK) {
                    pr_error("Error getting CU DIE offset %s\n", dwarf_errmsg(error));
                    goto out;
                }

                if (dwarf_get_loclist_offset_index_value(dbg, cu_die_offset,
                    index, &offset, &global_offset, &error) != DW_DLV_OK) {
                    pr_error("Error getting loclistx index: dwarf_get_loclist_offset_index_value: %s\n",
                             dwarf_errmsg(error));
                    goto out;
                }
            }
            break;
            case DW_FORM_exprloc:
                // TODO?
                break;
            case DW_FORM_block:
            case DW_FORM_block1:
            case DW_FORM_block2:
            case DW_FORM_block4:
                // TODO?
            default:
                // Skip other forms
                break;
        }
        // TODO: Do we need to handle addrx?
        (void)addrx;

        skip_form_content(attr_form, &current_pos, address_size, elf_info->dwarf_offset_size, end);
    }

    r = 0;
out:
    if (attrs) {
        dwarf_dealloc(dbg, attrs, DW_DLA_LIST);
    }
    return r < 0 ? r : (ssize_t)n_updated;
}

static ssize_t process_die_and_children(ElfInfo *elf_info, AdjInfo *adj_info,
                                        Dwarf_Die cu_die, Dwarf_Die die,
                                        Dwarf_Half address_size, Dwarf_Half offset_size) {
    size_t n_updated = 0;
    Dwarf_Die child = NULL;
    Dwarf_Error error = NULL;

    int r = -1;

    ssize_t n_updated_offsets = update_attribute_offsets(elf_info, adj_info, cu_die, die,
                                                         address_size, offset_size);
    if (n_updated_offsets < 0) {
        goto out;
    }

    n_updated += n_updated_offsets;

    // Process children
    switch (dwarf_child(die, &child, &error)) {
    case DW_DLV_ERROR:
        pr_error("Error getting child DIE: %s\n", dwarf_errmsg(error));
        goto out;
    case DW_DLV_NO_ENTRY:
        r = 0;
        goto out;
    }

    int res;
    do {
        ssize_t n_updated_child = process_die_and_children(elf_info, adj_info, cu_die, child,
                                                            address_size, offset_size);
        if (n_updated_child < 0)
            goto out;
        n_updated += n_updated_child;
    } while ((res = dwarf_siblingof(elf_info->dbg, child, &child, &error)) == DW_DLV_OK);

    if (res == DW_DLV_ERROR) {
        pr_error("Error getting sibling DIE: %s\n", dwarf_errmsg(error));
        goto out;
    }

    r = 0;
out:
    return r < 0 ? r : (ssize_t)n_updated;
}

// Function to add 'val' to the value at the given 'addr' in the ELF file for PROGBITS sections
static int adjust_addr_in_payload(ElfInfo *info, AdjInfo *adj_info, GElf_Addr old_addr) {
    assert(adj_info->sections_adjusted);

    GElf_Addr addr = calc_adjusted_addr(adj_info, old_addr);

    // Iterate through all sections to find the PROGBITS sections
    for (size_t i = 0; i < info->shnum; ++i) {
        struct elf_section *sec = &info->sections[i];
        GElf_Shdr *shdr = &sec->shdr;

        // Check if the section type is SHT_PROGBITS and if the address is within the section range
        switch (shdr->sh_type) {
            case SHT_PROGBITS: 
            case SHT_INIT_ARRAY:
            case SHT_FINI_ARRAY:
                break;
            default:
                continue;
        }
        
        if (addr >= shdr->sh_addr && addr < (shdr->sh_addr + shdr->sh_size)) {
            // Get the section descriptor
            if (get_section_data(sec) < 0) {
                pr_error("Failed to get section data\n");
                return -1;
            }

            // Calculate the offset of 'addr' within this section
            size_t offset_in_section = addr - shdr->sh_addr;

            // Check bounds to ensure that offset_in_section + sizeof(GElf_Addr) is within range
            if (offset_in_section + sizeof(GElf_Addr) > sec->size) {
                pr_error("Address out of bounds within section data.\n");
                return -1;
            }

            // Modify the value at the target address
            GElf_Addr *target_addr_ptr = (GElf_Addr *)((char *)sec->data + offset_in_section);
            GElf_Addr mem_val = *target_addr_ptr;

            if (mem_val < adj_info->old_exec_vaddr) {
                // No need to adjust this value
                return 0;
            }

            *target_addr_ptr += adj_info->vaddr_delta;

            mark_section_dirty(sec);

            return 0;
        }
    }
    pr_error("Address 0x%lx not found in any PROGBITS section\n", addr);
    return -1;
}

static void free_elf_info(ElfInfo *elf_info) {
    Dwarf_Error err;
    if (dwarf_finish(elf_info->dbg, &err)) {
        pr_error("Failed to finish DWARF: %s\n", dwarf_errmsg(err));
    }
    free(elf_info->first_section_per_segment);
    free(elf_info->phdrs);
    free(elf_info->sections);
    elf_info->first_section_per_segment = NULL;
    elf_info->phdrs = NULL;
    elf_info->sections = NULL;
}

static int find_hugifiable_segment(ElfInfo *info) {
    ssize_t idx = -1;
    for (size_t i = 0; i < info->phnum; i++) {
        if (info->phdrs[i].p_type == PT_LOAD && info->phdrs[i].p_flags & PF_X) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        pr_error("No executable segment found\n");
        return -1;
    }

    // Check all sections before the segment start address that their type is in the relocatable_section_types array
    for (size_t i = 0; i < info->shnum; i++) {
        struct elf_section *sec = &info->sections[i];

        if (sec->shdr.sh_addr >= info->phdrs[idx].p_vaddr)
            break;

        bool found = false;

        for (size_t j = 0; j < array_size(relocatable_section_types); j++) {
            if (sec->shdr.sh_type == relocatable_section_types[j].type &&
                (relocatable_section_types[j].name == NULL ||
                 strcmp(sec->name, relocatable_section_types[j].name) == 0)) {
                found = true;
                break;
            }
        }

        if (!found) {
            pr_error("Section %s is not relocatable\n", sec->name);
            return -1;
        }
    }

    return idx;
}

static void mark_first_sections_for_segments(ElfInfo *info) {
    if (!info || !info->phdrs || !info->sections) {
        return;  // Invalid input
    }

    // Allocate an array to store the first section index for each segment
    ssize_t *first_section = calloc(info->phnum, sizeof(ssize_t));
    if (!first_section) {
        return;  // Memory allocation failed
    }

    // Initialize all entries to -1 (no section found yet)
    for (size_t i = 0; i < info->phnum; i++) {
        first_section[i] = -1;
    }

    // Iterate through all sections
    for (size_t i = 0; i < info->shnum; i++) {
        GElf_Shdr *shdr = &info->sections[i].shdr;
        
        // Check each segment
        for (size_t j = 0; j < info->phnum; j++) {
            GElf_Phdr *phdr = &info->phdrs[j];
            
            // Check if the section is within the segment's memory range
            if (shdr->sh_addr >= phdr->p_vaddr && 
                shdr->sh_addr < phdr->p_vaddr + phdr->p_memsz) {
                
                // If this is the first section found for this segment, mark it
                if (first_section[j] == -1) {
                    first_section[j] = i;
                }
                
                // We can break here if we only want to mark the first section
                // that appears in the segment. Remove this break if you want
                // to find the earliest section by file offset.
                break;
            }
        }
    }

    // Store the results in the ElfInfo structure
    // You'll need to add this field to your ElfInfo struct
    info->first_section_per_segment = first_section;
}

static int parse_elf(ElfInfo *elf_info) {
    int r = -1;
    free_elf_info(elf_info);

    Elf *elf = elf_info->elf;
    
    if (gelf_getehdr(elf, &elf_info->ehdr) == NULL) {
        pr_error("gelf_getehdr failed: %s\n", elf_errmsg(-1));
        goto out;
    }

    if (elf_getphdrnum(elf, &elf_info->phnum) != 0) {
        pr_error("elf_getphdrnum failed: %s\n", elf_errmsg(-1));
        goto out;
    }

    elf_info->phdrs = malloc(elf_info->phnum * sizeof(GElf_Phdr));
    for (size_t i = 0; i < elf_info->phnum; i++) {
        if (gelf_getphdr(elf, i, &elf_info->phdrs[i]) == NULL) {
            pr_error("gelf_getphdr %ld failed: %s\n", i, elf_errmsg(-1));
            goto out;
        }
    }

    if (elf_getshdrnum(elf, &elf_info->shnum) != 0) {
        pr_error("elf_getshdrnum failed: %s\n", elf_errmsg(-1));
        goto out;
    }

    elf_info->sections = calloc(elf_info->shnum, sizeof(*elf_info->sections));
    for (size_t i = 0; i < elf_info->shnum; i++) {
        struct elf_section *sec = &elf_info->sections[i];
        sec->scn = elf_getscn(elf, i);
        if (sec->scn == NULL) {
            pr_error("parse_elf: elf_getscn: %s\n", elf_errmsg(-1));
            goto out;
        }

        if (gelf_getshdr(sec->scn, &sec->shdr) == NULL) {
            pr_error("gelf_getshdr: %s\n", elf_errmsg(-1));
            goto out;
        }

        if (get_section_data_uncached(sec) < 0) {
            pr_error("Failed to get section data\n");
            goto out;
        }
        
        get_section_data(sec);

        mark_section_dirty(sec);

        sec->name = elf_strptr(elf, elf_info->ehdr.e_shstrndx, sec->shdr.sh_name);
        if (sec->name == NULL) {
            sec->name = "<unknown>";
        }
    }

    ssize_t hugifiable_segment = find_hugifiable_segment(elf_info);
    if (hugifiable_segment == -1) {
        pr_error("%s : No hugifiable segment found\n", elf_info->filename);
        goto out;
    }

    // Find the first loadable segment
    elf_info->first_load_index = -1;
    for (size_t i = 0; i < elf_info->phnum; i++) {
        if (elf_info->phdrs[i].p_type == PT_LOAD) {
            elf_info->first_load_index = i;
            break;
        }
    }

    // Find the first executable segment
    elf_info->exec_index = -1;
    for (size_t i = 0; i < elf_info->phnum; i++) {
        if (elf_info->phdrs[i].p_flags & PF_X) {
            elf_info->exec_index = i;
            break;
        }
    }
    if (elf_info->exec_index == -1) {
        pr_error("No executable segment found\n");
        goto out;
    }

    mark_first_sections_for_segments(elf_info);
    // Find the debug_loc section index
    Dwarf_Error err;
    int dwf_r = dwarf_elf_init(elf, DW_DLC_READ, NULL, NULL, &elf_info->dbg, &err);
    
    switch (dwf_r) {
        case DW_DLV_NO_ENTRY:
            break;
        case DW_DLV_ERROR:
            pr_error("dwarf_elf_init() failed: %s\n", dwarf_errmsg(err));
            goto out;
    }

    if (dwarf_get_offset_size(elf_info->dbg, &elf_info->dwarf_offset_size, &err) != DW_DLV_OK) {
        pr_error("Error getting offset size: %s\n", dwarf_errmsg(err));
        goto out;
    }

    r = 0;
out:
    return r;
}

static void adjust_program_headers(ElfInfo *info, AdjInfo *adj_info) {
    assert(info->first_load_index >= 0 && "No loadable segment found");
    assert(info->exec_index >= 0 && "No executable segment found");

    for (size_t i = 0; i < info->phnum; i++) {
        GElf_Phdr *phdr = &info->phdrs[i];

        if (i == (size_t)info->first_load_index) {
            phdr->p_align = HUGE_PAGE_SIZE;
        }
 
        if (phdr->p_vaddr >= (size_t)adj_info->old_exec_vaddr) {
            // Program headers that need to be adjusted
            if (i == (size_t)info->exec_index) {
                phdr->p_memsz = round_up(phdr->p_memsz, HUGE_PAGE_SIZE);
                if (adj_info->adjust_offsets) {
                    phdr->p_filesz = phdr->p_memsz;
                    phdr->p_align = HUGE_PAGE_SIZE;
                }
            } 

            phdr->p_vaddr += adj_info->vaddr_delta;
            phdr->p_paddr += adj_info->vaddr_delta;
        }

        if (adj_info->adjust_offsets) {
            // The executable segment is aligned to huge page, the following
            // segments should take into account also the additional padding
            // that is then added at the beginning of the executable segment.
            if (phdr->p_offset == adj_info->old_exec_offset) {
                phdr->p_offset += adj_info->segment_offset_delta;
                phdr->p_vaddr = round_down(phdr->p_vaddr, HUGE_PAGE_SIZE);
                phdr->p_paddr = round_down(phdr->p_paddr, HUGE_PAGE_SIZE);
            } else if (phdr->p_offset > adj_info->old_exec_offset) {
                phdr->p_offset += adj_info->section_offset_delta;
            }
        }
    }
}

static void dirty_all_sections(ElfInfo *elf_info) {
    for (size_t i = 0; i < elf_info->shnum; i++) {
        struct elf_section *sec = &elf_info->sections[i];
        if (is_section_no_data(sec)) {
            continue;
        }
        get_section_data(sec);
        mark_section_dirty(sec);
    }
}

static void adjust_section_headers(ElfInfo *info, AdjInfo *adj_info) {
    size_t n_updated = 0;
    for (size_t i = 1; i < info->shnum; i++) {
        struct elf_section *sec = &info->sections[i];
        uint64_t old_addr = sec->shdr.sh_addr;
        uint64_t new_addr = calc_adjusted_addr(adj_info, old_addr);

        if (old_addr != new_addr) {
            n_updated++;
            pr_debug("Adjusting section %s from 0x%lx to 0x%lx\n", sec->name, old_addr, new_addr);
            sec->shdr.sh_addr = new_addr;
        }

        if (adj_info->adjust_offsets && sec->shdr.sh_offset >= adj_info->old_exec_offset) {
            sec->shdr.sh_offset += adj_info->section_offset_delta;
        }
    }
    pr_info("Adjusted %zu section headers\n", n_updated);

    if (adj_info->adjust_offsets) {
        dirty_all_sections(info);
    }
    adj_info->sections_adjusted = true;

    // Move the section headers to the new location
    if (adj_info->adjust_offsets) {
        if (info->ehdr.e_shoff > adj_info->old_exec_offset) {
            info->ehdr.e_shoff = round_up(info->ehdr.e_shoff + adj_info->section_offset_delta, 8);
        } 
    }
}

static void adjust_entry_point(ElfInfo *info, AdjInfo *adj_info) {
    uint64_t old_addr = info->ehdr.e_entry;
    uint64_t new_addr = calc_adjusted_addr(adj_info, old_addr);

    if (old_addr != new_addr) {
        pr_debug("Adjusting entry point from 0x%lx to 0x%lx\n", old_addr, new_addr);
        info->ehdr.e_entry = new_addr;
        pr_info("Adjusted entry point\n");
    }
}

static int adjust_dynamic_section(ElfInfo *info, AdjInfo *adj_info) {
    size_t n_updated = 0;
    int r = -1;

    for (size_t i = 0; i < info->shnum; i++) {
        GElf_Shdr *shdr = &info->sections[i].shdr;
        struct elf_section *sec = &info->sections[i];

        if (sec->shdr.sh_type != SHT_DYNAMIC) {
            continue;
        }

        invalidate_section_data_cache(info, sec);
        
        assert(sec->_data_count <= 1 && "Multiple data entries in dynamic section are unchecked");
        for (size_t k = 0; k < sec->_data_count; k++) {
            Elf_Data *data = sec->_data[k];
            GElf_Dyn dyn;
            int ndyn = shdr->sh_size / shdr->sh_entsize;

            for (int j = 0; j < ndyn; j++) {
                if (gelf_getdyn(data, j, &dyn) != &dyn) {
                    pr_error("gelf_getdyn failed: %s\n", elf_errmsg(-1));
                    goto out;
                }

                switch (dyn.d_tag) {
                    case DT_PLTGOT:
                    case DT_HASH:
                    case DT_STRTAB:
                    case DT_SYMTAB:
                    case DT_RELA:
                    case DT_INIT:
                    case DT_FINI:
                    case DT_REL:
                    case DT_JMPREL:
                    case DT_INIT_ARRAY:
                    case DT_FINI_ARRAY:
                    case DT_X86_64_PLT:
                    {
                        uint64_t old_addr = dyn.d_un.d_ptr;
                        uint64_t new_addr = calc_adjusted_addr(adj_info, old_addr);

                        if (old_addr != new_addr) {
                            pr_debug("Updating 0x%lx -> 0x%lx (dynamic section)\n", old_addr, new_addr);
                            dyn.d_un.d_ptr = new_addr;
                            n_updated++;

                            if (gelf_update_dyn(data, j, &dyn) == 0) {
                                pr_error("gelf_update_dyn failed: %s\n", elf_errmsg(-1));
                                goto out;
                            }
                        }
                        break;
                    }
                }
            }
        }
        mark_section_dirty(sec);
    }
    if (n_updated > 0) {
        pr_info("Updated %zu dynamic section entries\n", n_updated);
    }
    r = 0;
out:
    return r;
}

static int adjust_symbols(ElfInfo *info, AdjInfo *adj_info) {
    size_t n_updated = 0;
    int r = -1;

    for (size_t i = 0; i < info->shnum; i++) {
        struct elf_section *sec = &info->sections[i];
        GElf_Shdr *shdr = &sec->shdr;

        switch (shdr->sh_type) {
            case SHT_SYMTAB:
            case SHT_DYNSYM:
                break;
            default:
                continue;
        }
        
        invalidate_section_data_cache(info, sec);
        
        assert(sec->_data_count <= 1 && "Multiple data entries in symbol section are unchecked");
        for (size_t k = 0; k < sec->_data_count; k++) {
            Elf_Data *data = sec->_data[k];

            int sym_count = shdr->sh_size / shdr->sh_entsize;
            for (int j = 0; j < sym_count; j++) {
                GElf_Sym sym;
                if (gelf_getsym(data, j, &sym) != &sym) {
                    pr_error("gelf_getsym failed: %s\n", elf_errmsg(-1));
                    goto out;
                }

                uint64_t old_addr = sym.st_value;
                uint64_t new_addr = calc_adjusted_addr(adj_info, old_addr);

                if (old_addr != new_addr) {
                    pr_debug("Updating 0x%lx -> 0x%lx (symbol)\n", old_addr, new_addr);
                    sym.st_value = new_addr;
                    n_updated++;
                    if (gelf_update_sym(data, j, &sym) == 0) {
                        pr_error("gelf_update_sym failed: %s\n", elf_errmsg(-1));
                        goto out;
                    }
                }
            }
        }
        mark_section_dirty(sec);
    }
    if (n_updated > 0)
        pr_info("Updated %zu symbols\n", n_updated);
    r = 0;
out:
    return r;
}

static int adjust_relocations(ElfInfo *info, AdjInfo *adj_info) {
    size_t n_updated = 0;
    int r = -1;

    for (size_t i = 0; i < info->shnum; i++) {
        struct elf_section *sec = &info->sections[i];
        GElf_Shdr *shdr = &sec->shdr;

        if (shdr->sh_type != SHT_RELA) {
            continue;
        }

        invalidate_section_data_cache(info, sec);
        assert(sec->_data_count <= 1 && "Multiple data entries in relocation section are unchecked");
        for (size_t k = 0; k < sec->_data_count; k++) {
            Elf_Data *data = sec->_data[k];

            int rela_count = shdr->sh_size / shdr->sh_entsize;
            for (int j = 0; j < rela_count; j++) {
                GElf_Rela rela;

                if (gelf_getrela(data, j, &rela) != &rela) {
                    pr_error("gelf_getrela failed: %s\n", elf_errmsg(-1));
                    goto out;
                }
                
                GElf_Addr old_offset = rela.r_offset;
                GElf_Addr new_offset = calc_adjusted_addr(adj_info, old_offset);

                if (old_offset != new_offset) {
                    rela.r_offset = new_offset;
                    n_updated++;
                    pr_debug("Updating 0x%lx -> 0x%lx (rela offset)\n", old_offset, new_offset);
                    
                    if (gelf_update_rela(data, j, &rela) == 0) {
                        pr_error("gelf_update_rela failed: %s\n", elf_errmsg(-1));
                        goto out;
                    }
                }

                switch (ELF64_R_TYPE(rela.r_info)) {
                    case R_X86_64_RELATIVE64:
                    case R_X86_64_RELATIVE:
                    case R_X86_64_IRELATIVE:
                        Elf64_Sxword old_addend = rela.r_addend;
                        Elf64_Sxword new_addend = calc_adjusted_addr(adj_info, old_addend);

                        if (old_addend != new_addend) {
                            pr_debug("Updating 0x%lx -> 0x%lx (rela addend)\n", old_addend, new_addend);
                            rela.r_addend = new_addend;
                            n_updated++;

                            if (gelf_update_rela(data, j, &rela) == 0) {
                                pr_error("gelf_update_rela failed: %s\n", elf_errmsg(-1));
                                goto out;
                            }
                        }
                        // fallthrough
                    case R_X86_64_JUMP_SLOT:
                        if (adjust_addr_in_payload(info, adj_info, old_offset)) {
                            goto out;
                        }
                        break;
                    case R_X86_64_64:
                    case R_X86_64_GLOB_DAT:
                    case R_X86_64_TPOFF64:
                    case R_X86_64_DTPMOD64:
                    case R_X86_64_DTPOFF64:
                        // do nothing
                        break;
                    default:
                        // crash
                        pr_error("Unsupported relocation type: %ld\n", ELF64_R_TYPE(rela.r_info));
                        goto out;
                }
            }
        }
        mark_section_dirty(sec);
    }
    if (n_updated > 0)
        pr_info("Updated %zu relocations\n", n_updated);
    r = 0;
out:
    return r;
}

static int adjust_relr(ElfInfo *info, AdjInfo *adj_info) {
    size_t n_updated_direct = 0;
    size_t n_updated_indirect = 0;
    int r = -1;

    for (size_t i = 0; i < info->shnum; i++) {
        struct elf_section *sec = &info->sections[i];

        if (sec->shdr.sh_type == SHT_RELR) {
            if (get_section_data(&info->sections[i]) < 0) {
                goto out;
            }

            size_t num_entries = sec->size / sizeof(GElf_Relr);

            GElf_Addr addr = 0;

            for (size_t ndx = 0; ndx < num_entries; ndx++) {
                GElf_Relr *p_relr = &((GElf_Relr *)sec->data)[ndx];
                GElf_Relr relr = *p_relr;
                
                if ((relr & 1) == 0) {
                    // Delta entry
                    addr = relr;
                    GElf_Relr new_relr = calc_adjusted_addr(adj_info, relr);

                    if (relr != new_relr) {
                        pr_debug("Updating: 0x%lx -> 0x%lx (relr)\n", relr, new_relr);
                        *p_relr = new_relr;
                        n_updated_direct++;
                    }
                    // We still did not update the section offsets, so we use the old
                    // address when updating.
                    if (adjust_addr_in_payload(info, adj_info, addr))
                        goto out;
                    addr += sizeof(GElf_Addr);
                } else {
                    // Bitmap entry
                    for (long i = 0; (relr >>= 1) != 0; i++) {
                        GElf_Addr bitmap_addr = addr + i * sizeof(GElf_Addr);

                        if ((relr & 1) != 0 && bitmap_addr > adj_info->old_exec_vaddr) {
                            if (adjust_addr_in_payload(info, adj_info, bitmap_addr)) {
                                goto out;
                            }
                            n_updated_indirect++;
                        }
                    }
                    addr += (CHAR_BIT * sizeof(GElf_Addr) - 1) * sizeof(GElf_Addr);
                }
            }
            update_section_data(info, sec);
        }
    }
    if (n_updated_direct > 0) {
        pr_info("Updated %zu relr entries\n", n_updated_direct);
    }
    if (n_updated_indirect > 0) {
        pr_info("Updated %zu relr bitmap entries\n", n_updated_indirect);
    }
    r = 0;
out:
    return r;
}

static int adjust_stapsdt(ElfInfo *elf_info, AdjInfo *adj_info) {
    size_t n_updated = 0;
    struct elf_section *sec = get_section(elf_info, ".note.stapsdt");
    if (sec == NULL) {
        return 0;
    }
    assert(sec->shdr.sh_type != SHT_PROGBITS);
    
    int r = -1;
    size_t adj = 0;
    while (adj + sizeof(Elf64_Nhdr) <= sec->size) {
        Elf64_Nhdr *nhdr = (Elf64_Nhdr *)(sec->data + adj);
        
        size_t name_size = round_up(nhdr->n_namesz, 4);
        size_t desc_size = round_up(nhdr->n_descsz, 4);
        size_t entry_size = sizeof(Elf64_Nhdr) + name_size + desc_size;
        
        if (adj + entry_size > sec->size) {
            break;
        }

        char *desc = (char *)(sec->data + adj + sizeof(Elf64_Nhdr) + name_size);
        
        if (nhdr->n_type == NT_STAPSDT) {
            uint64_t *addresses = (uint64_t *)desc;  // The three addresses are at the start
            
            for (int i = 0; i < 3; i++) {
                uint64_t old_addr = addresses[i];
                uint64_t new_addr = calc_adjusted_addr(adj_info, old_addr);
                if (new_addr != old_addr) {
                    addresses[i] = new_addr;
                    n_updated++;
                    pr_debug("Updating 0x%lx -> 0x%lx (sdt)\n", old_addr, new_addr);
                }
            }
        }
        adj += entry_size;
    }

    if (n_updated > 0) {
        if (update_section_data(elf_info, sec)) {
            goto out;
        }
        pr_info("Updated %zu stapsdt addresses\n", n_updated);
    }
    r = 0;
out:
    return r;
}

static int get_section_data_uncached(struct elf_section *sec) {
    if (sec->_data != NULL)
        return 0;
    
    size_t n_data_desc = 0;
    size_t index = 0;

    Elf_Data *prev = NULL;
    // Count how many data descriptors are in the section
    while ((prev = elf_getdata(sec->scn, prev)) != NULL) {
        n_data_desc++;
    }
    sec->_data_count = n_data_desc;
    assert(n_data_desc > 0 && "No data descriptors found in section");
    assert(n_data_desc == 1 && "Multiple data descriptors in section are still not supported");
    sec->_data = malloc(index * sizeof(sec->_data));
    assert(sec->_data && "Failed to allocate memory for Elf_Data array");

    prev = NULL;
    for (size_t i = 0; i < n_data_desc; i++) {
        Elf_Data *data = elf_getdata(sec->scn, prev);
        sec->_data[i] = data;
        prev = data;
        // copy the data and create a new Elf_Data
        if (is_section_no_data(sec)) {
            continue;
        }
        Elf_Data *newdata = elf_newdata(sec->scn);
        newdata->d_align = data->d_align;
        newdata->d_off = data->d_off;
        newdata->d_type = data->d_type;
        newdata->d_version = data->d_version;
        newdata->d_buf = malloc(data->d_size);
        newdata->d_size = data->d_size;
        memcpy(newdata->d_buf, data->d_buf, data->d_size);
        sec->_data[0]->d_size = 0;
        sec->_data[0] = newdata;
    }

    return 0;
}

static int update_section_data(ElfInfo *elf_info, struct elf_section *sec) {
    unsigned char *compressed_buf = NULL;

    if (is_section_no_data(sec)) {
        return 0;
    }

    Elf64_Chdr *org_chdr = (Elf64_Chdr *)sec->_data[0]->d_buf;

    if (is_section_compressed(sec)) {
        // Recompress the section
        unsigned long compressed_size;

        switch (org_chdr->ch_type) {
            case ELFCOMPRESS_ZLIB:
                compressed_size = compressBound(sec->size);
                compressed_buf = malloc(compressed_size + sizeof(Elf64_Chdr));

                if (compress2(compressed_buf + sizeof(Elf64_Chdr), &compressed_size, sec->data, sec->size, 9) != Z_OK) {
                    pr_error("Failed to compress %s section\n", sec->name);
                    goto do_err;
                }
                break;
            case ELFCOMPRESS_ZSTD:
                compressed_size = ZSTD_compressBound(sec->size);
                compressed_buf = malloc(compressed_size + sizeof(Elf64_Chdr));

                compressed_size = ZSTD_compress(compressed_buf + sizeof(Elf64_Chdr), compressed_size, sec->data, sec->size, 9);

                if (ZSTD_isError(compressed_size)) {
                    pr_error("Failed to compress %s section: %s\n", sec->name, 
                             ZSTD_getErrorName(compressed_size));
                    goto do_err;
                }
                break;
            default:
                pr_error("Unsupported compression type\n");
                goto do_err;
        }
        
        Elf64_Chdr *chdr = (Elf64_Chdr *)compressed_buf;
        *chdr = *org_chdr;
        chdr->ch_size = sec->size;

        Elf_Data *newdata = elf_newdata(sec->scn);
        newdata->d_align = 1;
        newdata->d_off = 0;
        newdata->d_type = ELF_T_BYTE;
        newdata->d_version = EV_CURRENT;
        newdata->d_buf = compressed_buf;
        newdata->d_size = compressed_size + sizeof(Elf64_Chdr);
        sec->_data[0]->d_size = 0;
        sec->_data[0] = newdata;
        if (update_elf_offsets(elf_info, sec, sec->_data[0]->d_size) < 0) {
            return -1;
        }

    } else {
        // TODO: handling of multiple data entries should probably merge them together.
        if (false) {
            if (sec->_data[0]->d_size > sec->size) {
                sec->_data[0] = malloc(sec->size);
            }
            memcpy(sec->_data[0]->d_buf, sec->data, sec->size);
        }
    }
    
    assert(sec->_data_count <= 1 && "Multiple data entries in section are unsupported");

    mark_section_data_dirty(sec);

    return 0;
do_err:
    free(compressed_buf);
    return -1;
}

static void *read_debug_table_length(void **p, bool *is_64bit, void *end) {
    uint64_t length = buf_uread(p, 4, end);
    bool _is_64bit = length == 0xffffffff;

    if (_is_64bit) {
        buf_uread(p, 8, end);
    }
    
    if (is_64bit)
        *is_64bit = _is_64bit;
    return *p + length;
}

// Returns the start if needed for offset calculation
static void *read_debug_header(ElfInfo *elf_info, void **p, void **unit_end,
                               uint16_t *version, uint8_t *address_size,
                               bool *is_64bit, void *end) {
    *unit_end = read_debug_table_length(p, is_64bit, end);
    void *unit_start = *p;

    if (unit_start == *unit_end) {
        *version = 0;
        *address_size = 0;
        goto out;
    }

    // Read version number
    *version = buf_uread(p, 2, end);

    // Handle version-specific reading of address size
    if (*version == 5) {
        *address_size = buf_uread(p, 1, end);  // Skip address_size
    } else {
        // For DWARF versions 2-4, address size is often implied (commonly 4 or 8 bytes)
        *address_size = elf_info->ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? 8 : 4;
    }

out:
    return unit_start;
}

static int adjust_debug_aranges(ElfInfo *elf_info, AdjInfo *adj_info)
{
    int r = -1;
    size_t n_updated = 0;
    
    struct elf_section *sec = get_debug_section(elf_info, DW_SECT_ARANGES);

    if (!sec) {
        return 0;
    }

    void *end = sec->data + sec->size;
    void *p = sec->data;

    while (p < end) {
        // Parse compilation unit header
        void *unit_end = read_debug_table_length(&p, NULL, end);
        void *unit_start = p;
        if (unit_start == unit_end) {
            break;
        }
        buf_uread(&p, 2, end); // Skip version
        buf_uread(&p, 4, end); // Skip debug_info_offset
        uint8_t address_size = buf_uread(&p, 1, end);
        buf_uread(&p, 1, end);  // Skip segment_size

        // Align to the maximum of (address_size, 4)
        size_t align_size = (address_size > 4) ? address_size : 4;
        buf_align_offset(&p, align_size, sec->data, unit_end);

        // Process address ranges
        while (p < unit_end) {
            n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "aranges");
            buf_uread(&p, address_size, unit_end);  // Skip length
        }

        // Move to the next compilation unit (if any)
        assert(p == unit_end && "Failed to parse aranges");
    }

    if (n_updated > 0) {
        if (update_section_data(elf_info, sec) != 0) {
            goto out;
        }
        pr_info("Updated %zu aranges\n", n_updated);
    }

    r = 0;
out:
    return r;
}

static int adjust_debug_line(ElfInfo *elf_info, AdjInfo *adj_info) {
    int r = -1;
    size_t n_updated = 0;

    struct elf_section *sec = get_debug_section(elf_info, DW_SECT_LINE);

    if (!sec) {
        return 0;
    }

    void *p = sec->data;
    void *end = sec->data + sec->size;

    while (p < end) {
        uint16_t version;
        bool is_64bit;
        void *unit_start, *unit_end;
        uint8_t address_size;

        unit_start = read_debug_header(elf_info, &p, &unit_end, &version, &address_size, &is_64bit, end);
        if (unit_start == unit_end) {
            break;
        }
        assert(version >= 2 && version <= 5);  // Supported DWARF versions
        if (version >= 5) {
            buf_uread(&p, 1, unit_end);  // Skip segment_selector_size
        }
        uint64_t header_length = buf_uread(&p, is_64bit ? 8 : 4, unit_end);

        const void *header_start = p;

        buf_uread(&p, 1, unit_end); // Skip minimum_instruction_length
        if (version >= 4) {
            buf_uread(&p, 1, unit_end); // Skip maximum_operations_per_instruction
        }
        buf_uread(&p, 1, unit_end); // Skip default_is_stmt
        buf_sread(&p, 1, unit_end); // Skip line_base
        buf_uread(&p, 1, unit_end); // Skip line_range
        uint8_t opcode_base = buf_uread(&p, 1, unit_end);

        assert(opcode_base > 0);

        // Standard opcode lengths
        uint8_t standard_opcode_lengths[256];  // Max possible size
        for (int i = 1; i < opcode_base && p < unit_end; i++) {
            standard_opcode_lengths[i] = buf_uread(&p, 1, unit_end);
        }

        // For DWARF 5, handle the directory and file name tables differently
        if (version >= 5) {
            // Directory table
            uint8_t directory_entry_format_count = buf_uread(&p, 1, unit_end);

            uint64_t *content_types = malloc(directory_entry_format_count * sizeof(uint64_t));
            uint64_t *forms = malloc(directory_entry_format_count * sizeof(uint64_t));

            for (int i = 0; i < directory_entry_format_count; i++) {
                content_types[i] = buf_uleb128_decode(&p, unit_end);
                forms[i] = buf_uleb128_decode(&p, unit_end);
            }

            uint64_t directories_count = buf_uleb128_decode(&p, unit_end);

            for (uint64_t i = 0; i < directories_count; i++) {
                for (int j = 0; j < directory_entry_format_count; j++) {
                    skip_form_content(forms[j], &p, address_size, elf_info->dwarf_offset_size, unit_end);
                }
            }

            free(content_types);
            free(forms);

            // File name table
            uint8_t file_name_entry_format_count = buf_uread(&p, 1, unit_end);

            content_types = malloc(file_name_entry_format_count * sizeof(uint64_t));
            forms = malloc(file_name_entry_format_count * sizeof(uint64_t));

            for (int i = 0; i < file_name_entry_format_count; i++) {
                content_types[i] = buf_uleb128_decode(&p, unit_end);
                forms[i] = buf_uleb128_decode(&p, unit_end);
            }

            uint64_t file_names_count = buf_uleb128_decode(&p, unit_end);

            for (uint64_t i = 0; i < file_names_count; i++) {
                for (int j = 0; j < file_name_entry_format_count; j++) {
                    skip_form_content(forms[j], &p, address_size, elf_info->dwarf_offset_size, unit_end);
                }
            }

            free(content_types);
            free(forms);
        } else {
            // For DWARF 2-4, handle include_directories and file_names
            while (p < unit_end) {
                size_t len = buf_consume_string(&p, unit_end);  // Skip include_directory
                if (len == 0) {
                    break;
                }
            }

            while (p < unit_end) {
                size_t len = buf_consume_string(&p, unit_end);
                if (len == 0) {
                    break;
                }
                buf_uleb128_decode(&p, unit_end);  // dir_index
                buf_uleb128_decode(&p, unit_end);  // mtime
                buf_uleb128_decode(&p, unit_end);  // file_length
            }
        }

        // Ensure we've processed exactly header_length bytes
        assert((uintptr_t)p - (uintptr_t)header_start == header_length);

        // Parse the line number program
        while (p < unit_end) {
            uint8_t opcode = buf_uread(&p, 1, unit_end);

            if (opcode == 0) {  // Extended opcode
                uint64_t ext_length = buf_uleb128_decode(&p, unit_end);
                assert((uintptr_t)unit_end - (uintptr_t)p >= ext_length);
                
                uint8_t sub_opcode = buf_uread(&p, 1, unit_end);
                ext_length--;

                switch (sub_opcode) {
                    case DW_LNE_set_address:
                        n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "DW_LNE_set_address");
                        assert(ext_length == address_size);
                        break;
                    default:
                        buf_consume(&p, ext_length, unit_end);
                }
            } else if (opcode < opcode_base) {
                // Standard opcode
                for (int i = 0; i < standard_opcode_lengths[opcode] && p < unit_end; i++) {
                    buf_uleb128_decode(&p, unit_end);
                }
            } else {
                // Special opcode, no operands
            }
        }

        assert(p == unit_end);  // Ensure we've processed the entire unit
    }

    // Write back the modified .debug_line section
    if (n_updated > 0) {
        if (update_section_data(elf_info, sec) != 0) {
            goto out;
        }
        pr_info("Updated %zu .debug_line entries\n", n_updated);
    }

    r = 0;
out:
    return r;
}

static int adjust_debug_rnglists(ElfInfo *elf_info, AdjInfo *adj_info) {
    size_t n_updated = 0;
    struct elf_section *sec = get_debug_section(elf_info, DW_SECT_RNGLISTS);

    if (!sec)
        return 0;
    
    int r = -1;

    void *p = sec->data;
    void *end = sec->data + sec->size;

    while (p < end) {
        bool is_64bit;
        void *unit_end = read_debug_table_length(&p, &is_64bit, end);

        if (unit_end == p) {
            break;
        }

        uint16_t version = buf_uread(&p, 2, end);
        assert(version == 5);  // .debug_rnglists is only in DWARF 5
        uint8_t address_size = buf_uread(&p, 1, end);
        buf_uread(&p, 1, end); // Skip segment_selector_size
        uint32_t offset_entry_count = buf_uread(&p, 4, end);

        // Skip offset entries
        p += offset_entry_count * (is_64bit ? 8 : 4);

        while (p < unit_end) {
            uint8_t range_list_entry = buf_uread(&p, 1, unit_end);

            switch (range_list_entry) {
                case DW_RLE_end_of_list:
                    break;
                case DW_RLE_base_addressx:
                    buf_uleb128_decode(&p, unit_end);  // Skip index
                    break;
                case DW_RLE_startx_endx:
                case DW_RLE_startx_length:
                case DW_RLE_offset_pair:
                    buf_uleb128_decode(&p, unit_end);  // Skip start index/offset
                    buf_uleb128_decode(&p, unit_end);  // Skip end index/length
                    break;
                case DW_RLE_base_address:
                    n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "DW_RLE_base_address");
                    break;
                case DW_RLE_start_end:
                    n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "DW_RLE_start_end.start");
                    n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "DW_RLE_start_end.end");
                    break;
                case DW_RLE_start_length:
                    n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "DW_RLE_start_length.start");
                    buf_uleb128_decode(&p, unit_end);  // Length doesn't need adjustment
                    break;
                default:
                    pr_error("Unknown range list entry: 0x%x\n", range_list_entry);
                    goto out;
            }
        }

        assert(p == unit_end);  // Ensure we've processed the entire unit
    }

    if (n_updated > 0) {
        if (update_section_data(elf_info, sec) != 0) {
            goto out;
        }
        pr_info("Updated %zu rnglist entries\n", n_updated);
    }

    r = 0;

out:
    return r;
}

typedef struct {
    uint64_t offset;
    uint8_t address_size;
    uint64_t unit_size;
} UnitInfo;

static int compare_unit_info(const void *a, const void *b) {
    return ((const UnitInfo*)a)->offset - ((const UnitInfo*)b)->offset;
}

static UnitInfo* find_unit(UnitInfo *units, size_t unit_count, uint64_t target_offset) {
    size_t left = 0;
    size_t right = unit_count;

    while (left < right) {
        size_t mid = left + (right - left) / 2;
        if (units[mid].offset <= target_offset) {
            if (mid == unit_count - 1 || units[mid + 1].offset > target_offset) {
                return &units[mid];
            }
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    return NULL;
}

static int adjust_debug_loclists(ElfInfo *elf_info, AdjInfo *adj_info) {
    size_t n_updated = 0;
    int r = -1;
    struct elf_section *sec = get_debug_section(elf_info, DW_SECT_LOCLISTS);
 
    if (!sec)
        return 0;

    void *p = sec->data;
    void *end = sec->data + sec->size;

    // First pass: collect unit information
    UnitInfo *units = NULL;
    size_t unit_count = 0, unit_capacity = 0;
    while (p < end) {
        void *unit_start, *unit_end;
        bool is_64bit;
        uint8_t address_size;
        uint16_t version;
        
        unit_start = read_debug_header(elf_info, &p, &unit_end, &version, &address_size, &is_64bit, end);
        if (unit_start == unit_end) {
            break;  // End of all lists
        }
        assert(version == 5 && "Only DWARF 5 is supported");

        if (unit_count >= unit_capacity) {
            unit_capacity = unit_capacity ? unit_capacity * 2 : 16;
            units = realloc(units, unit_capacity * sizeof(UnitInfo));
            if (!units) {
                pr_error("Memory allocation failed\n");
                goto out;
            }
        }

        units[unit_count].offset = unit_start - sec->data;
        units[unit_count].address_size = address_size;
        units[unit_count].unit_size = unit_end - unit_start;
        unit_count++;

        p = unit_end;
    }

    // Sort units by offset
    qsort(units, unit_count, sizeof(UnitInfo), compare_unit_info);

    // Second pass: process location lists based on collected offsets
    offset_entry *entry;
    for (entry = elf_info->loclist_offsets; entry != NULL; entry = entry->hh.next) {
        UnitInfo *unit = find_unit(units, unit_count, entry->offset);
        
        if (!unit) {
            pr_error("Could not find unit for offset 0x%llx\n", (unsigned long long)entry->offset);
            continue;
        }

        // Sanity check: ensure the offset is within the unit's bounds
        if (entry->offset >= unit->offset + unit->unit_size) {
            pr_error("Offset 0x%llx is outside the bounds of its unit (0x%llx - 0x%llx)\n",
                     (unsigned long long)entry->offset,
                     (unsigned long long)unit->offset,
                     (unsigned long long)(unit->offset + unit->unit_size));
            continue;
        }

        p = sec->data + entry->offset;
        uint8_t address_size = unit->address_size;
        void *unit_end = sec->data + unit->offset + unit->unit_size;

        bool is_end_of_list = false;
        while (p < unit_end && !is_end_of_list) {
            uint8_t entry_type = buf_uread(&p, 1, unit_end);

            switch (entry_type) {
                case DW_LLE_end_of_list:
                    is_end_of_list = true;
                    break;
                case DW_LLE_base_addressx:
                    buf_uleb128_decode(&p, unit_end);
                    break;
                case DW_LLE_startx_endx:
                case DW_LLE_startx_length:
                case DW_LLE_offset_pair:
                    buf_uleb128_decode(&p, unit_end);
                    buf_uleb128_decode(&p, unit_end);
                    buf_consume_block_uleb128(&p, unit_end);
                    break;
                case DW_LLE_default_location:
                    p += buf_uleb128_decode(&p, unit_end);
                    break;
                case DW_LLE_base_address:
                    n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "DW_LLE_base_address");
                    break;
                case DW_LLE_start_end:
                    n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "DW_LLE_start_end.start");
                    n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "DW_LLE_start_end.end");
                    buf_consume_block_uleb128(&p, unit_end);
                    break;
                case DW_LLE_start_length:
                    n_updated += buf_update_addr(adj_info, &p, address_size, unit_end, "DW_LLE_start_length");
                    buf_uleb128_decode(&p, unit_end);
                    buf_consume_block_uleb128(&p, unit_end);
                    break;
                default:
                    pr_error("Unknown location list entry type: %d at offset %lx\n", entry_type,
                             (size_t)(p - sec->data) - 1);
                    goto out;
            }
        }
    }

    // Write back the modified .debug_loclists section
    if (n_updated > 0) {
        if (update_section_data(elf_info, sec) != 0) {
            goto out;
        }
        pr_info("Updated %zu .debug_loclists entries\n", n_updated);
    }
    
    r = 0;
out:
    free(units);
    return r;
}

static int write_elf(ElfInfo *elf_info) {
    int r = -1;
    
    // First update the sections - their sizes might have changed
    for (size_t i = 0; i < elf_info->shnum; i++) {
        struct elf_section *sec = &elf_info->sections[i];
        if (sec->is_dirty) {
            if (update_section_data(elf_info, sec) != 0) {
                goto out;
            }
        }
    }

    // Update ELF header
    if (gelf_update_ehdr(elf_info->elf, &elf_info->ehdr) == 0) {
        pr_error("gelf_update_ehdr: %s", elf_errmsg(-1));
        goto out;
    }

    // Update program headers
    for (size_t i = 0; i < elf_info->phnum; i++) {
        if (gelf_update_phdr(elf_info->elf, i, &elf_info->phdrs[i]) == 0) {
            pr_error("Failed to update program header %zu: %s\n", i, elf_errmsg(-1));
            goto out;
        }
    }

    // Update section headers
    for (size_t i = 0; i < elf_info->shnum; i++) {
        struct elf_section *sec = &elf_info->sections[i];
        if (gelf_update_shdr(sec->scn, &sec->shdr) == 0) {
            pr_error("Failed to update section header %zu: %s\n", i, elf_errmsg(-1));
            goto out;
        }
    }

    // Write changes to file
    if (elf_update(elf_info->elf, ELF_C_WRITE) < 0) {
        pr_error("elf_update failed: %s\n", elf_errmsg(-1));
        goto out;
    }
    r = 0;
out:
    return r;
}

static int update_buildid(ElfInfo *elf_info) {
    size_t n_updated = 0;

    struct elf_section *sec = find_section_by_name(elf_info, ".note.gnu.build-id");

    if (sec == NULL)
        return 0;

    int r = -1;
    assert(sec->shdr.sh_type == SHT_NOTE);

    size_t adj = 0;
    while (adj < sec->size) {
        Elf64_Nhdr *nhdr = (Elf64_Nhdr *)(sec->data + adj);
        char *name = (char *)(nhdr + 1);
        char *desc = name + round_up(nhdr->n_namesz, 4);

        if (nhdr->n_type == NT_GNU_BUILD_ID) {
            // The build ID data
            uint8_t *build_id = (uint8_t *)desc;
            n_updated++;

            build_id[nhdr->n_descsz - 1] ^= 0x2;    // Update the build ID
        }

        adj += sizeof(Elf64_Nhdr) + round_up(nhdr->n_namesz, 4) + round_up(nhdr->n_descsz, 4);
    }
    if (n_updated > 0) {
        if (update_section_data(elf_info, sec))
            goto out;
        pr_info("Updated %zu build-id entries\n", n_updated);
    }
    r = 0;
out:
    return r;
}

static int adjust_dwarf_info(ElfInfo *elf_info, AdjInfo *adj_info) {
    size_t n_updated = 0;
    Dwarf_Debug dbg = elf_info->dbg;
    Dwarf_Error error = {0};

    // Process DWARF information
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Die no_die = 0, cu_die = NULL;
    Dwarf_Bool is_info = 1;
    Dwarf_Half header_cu_type, offset_size, extension_size;
    Dwarf_Sig8 type_signature;
    Dwarf_Unsigned typeoffset;

    struct elf_section *sec = get_debug_section(elf_info, DW_SECT_INFO);

    if (!sec) {
        return 0;
    }

    int r = -1;

    while (1) {
        int res = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version_stamp,
                                     &abbrev_offset, &address_size, &offset_size,
                                     &extension_size, &type_signature, &typeoffset,
                                     &next_cu_header, &header_cu_type, &error);

        if (res == DW_DLV_NO_ENTRY) {
            break;
        }
        if (res != DW_DLV_OK) {
            pr_error("dwarf_next_cu_header_d: %s\n", dwarf_errmsg(error));
            goto out;
        }

        res = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, &error);
        if (res != DW_DLV_OK) {
            pr_error("Failed to get CU DIE: %s\n", dwarf_errmsg(error));
            goto out;
        }

        // Process DIEs and adjust addresses
        ssize_t n_updated_child = process_die_and_children(elf_info, adj_info, cu_die,
                                                            cu_die, address_size, offset_size);
        if (n_updated_child > 0) {
            n_updated += n_updated_child;
        }

        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
        cu_die = NULL;
    
        if (n_updated_child < 0)
            goto out;
    }

    if (update_section_data(elf_info, sec)) {
        goto out;
    }
    if (n_updated > 0) {
        pr_info("Updated %zu DIEs\n", n_updated);
    }
    
    r = 0;

out:
    if (cu_die)
        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
    return r;
}

static int adjust_elf(ElfInfo *info, AdjInfo *adj_info) {
    int r = -1;

    adjust_section_headers(info, adj_info);
    adjust_entry_point(info, adj_info);

    adjust_program_headers(info, adj_info);

    if (adjust_dynamic_section(info, adj_info))
        goto out;

    if (adjust_symbols(info, adj_info))
        goto out;

    if (adjust_relocations(info, adj_info))
        goto out;

    if (adjust_stapsdt(info, adj_info))
        goto out;

    if (adjust_relr(info, adj_info))
        goto out;

    if (adj_info->adjust_debug) {
        if (adjust_dwarf_info(info, adj_info))
            goto out;

        if (adjust_debug_aranges(info, adj_info))
            goto out;
        
        if (adjust_debug_line(info, adj_info))
            goto out;
        if (adjust_debug_loclists(info, adj_info))
            goto out;
        if (adjust_debug_rnglists(info, adj_info))
            goto out;
    }
    pr_info("Adjustments done\n");
    r = 0;
out:
    return r;
}

static int init_elf(ElfInfo *elf_info, const char *filename) {
    int r = -1;
    int fd = -1;
    
    if (elf_version(EV_CURRENT) == EV_NONE) {
        pr_error("elf_version failed: %s\n", elf_errmsg(-1));
        goto out;
    }

    elf_info->filename = filename;
    if ((fd = open(elf_info->filename, O_RDWR)) < 0) {
        perror("open");
        goto out;
    }

    if (fd < 0) {
        perror("open");
        goto out;
    }

    elf_info->fd = fd;

    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size < 0) {
        perror("lseek");
        goto out;
    }
    
    r = 0;
out:
    return r;
}

static int read_elf(ElfInfo *elf_info) {
    int r = -1;
    Elf *elf;

    if ((elf = elf_begin(elf_info->fd, ELF_C_RDWR, NULL)) == NULL) {
        pr_error("elf_begin failed: %s\n", elf_errmsg(-1));
        goto out;
    }

    if (elf_flagelf(elf, ELF_C_SET, ELF_F_LAYOUT) == 0) {
        pr_error("elf_flagelf failed: %s\n", elf_errmsg(-1));
        goto out;
    }

    elf_info->elf = elf;
    r = 0;
out:
    return r;
}

static void init_sections_ordered_by_offset(ElfInfo *elf_info) {
    elf_info->sections_ordered_by_offset = malloc(elf_info->shnum *
                                                  sizeof(*elf_info->sections_ordered_by_offset));
    for (size_t i = 0; i < elf_info->shnum; i++) {
        elf_info->sections_ordered_by_offset[i] = &elf_info->sections[i];
    }
    qsort(elf_info->sections_ordered_by_offset, elf_info->shnum,
          sizeof(*elf_info->sections_ordered_by_offset), compare_sections);
}

static int process_elf(const char *filename, uint32_t flags) {
    ElfInfo *elf_info = calloc(1, sizeof(ElfInfo));
    int r = -1;

    init_elf(elf_info, filename);

    if (read_elf(elf_info) != 0) {
        pr_error("Failed to read ELF file\n");
        goto out;
    }

    if (parse_elf(elf_info) != 0) {
        goto out;
    }

    init_sections_ordered_by_offset(elf_info);

    if (elf_info->ehdr.e_type != ET_DYN) {
        pr_error("Input file is not a process independent code\n");
        goto out;
    }

    // Get the current executable segment
    GElf_Phdr exec_phdr = elf_info->phdrs[elf_info->exec_index];

    // Round up the start of the segment to the next huge page boundary
    GElf_Addr new_exec_p_vaddr = round_up(exec_phdr.p_vaddr, HUGE_PAGE_SIZE);
    GElf_Off new_exec_p_offset = round_up(exec_phdr.p_offset, HUGE_PAGE_SIZE);

    // round up the old size according to exec_phdr.p_align
    uint64_t old_aligned_p_memsz = round_up(exec_phdr.p_memsz, exec_phdr.p_align);

    // New aligned size using huge page size (same for file and memory)
    uint64_t huge_aligned_size = round_up(exec_phdr.p_memsz, HUGE_PAGE_SIZE);
    
    uint64_t new_p_vaddr_end = new_exec_p_vaddr + huge_aligned_size;

    // Calculate the new starting address and offset (aligned to the huge page size)
    uint64_t new_exec_sec_vaddr = round_down(new_p_vaddr_end - old_aligned_p_memsz, exec_phdr.p_align);

    uint64_t segment_offset_delta = round_up_delta(exec_phdr.p_offset, HUGE_PAGE_SIZE);
    uint64_t section_offset_delta = segment_offset_delta + (new_exec_sec_vaddr % HUGE_PAGE_SIZE);

    pr_info("Original vaddr: 0x%lx, size: 0x%lx\n", exec_phdr.p_vaddr, exec_phdr.p_memsz);
    pr_info("New vaddr: 0x%lx, new size: 0x%lx\n", new_exec_sec_vaddr, huge_aligned_size);
    if (flags & FLAG_FILE_PADDING) {
        pr_info("Segment offset delta: 0x%lx, section offset delta: 0x%lx\n", segment_offset_delta, section_offset_delta);
        pr_info("New offset: 0x%lx\n", new_exec_p_offset);
    }

    AdjInfo adj_info = {
        .old_exec_vaddr = exec_phdr.p_vaddr,
        .vaddr_delta = new_exec_sec_vaddr - exec_phdr.p_vaddr,
        .old_exec_offset = exec_phdr.p_offset,
        .segment_offset_delta = segment_offset_delta,
        .section_offset_delta = section_offset_delta,
        .adjust_offsets = flags & FLAG_FILE_PADDING,
        .adjust_debug = flags & FLAG_DEBUG_UPDATE,
    };

    // Adjust the ELF structure
    if (adjust_elf(elf_info, &adj_info) != 0) {
        pr_error("Failed to adjust ELF file\n");
        goto out;
    }

    update_buildid(elf_info);

    // Write changes back to the ELF file
    if (write_elf(elf_info)) {
        pr_error("Failed to write ELF file\n");
        goto out;
    }

    r = 0;
out:
    elf_end(elf_info->elf);
    close(elf_info->fd);
    free_elf_info(elf_info);
    return r;
}

static void detailed_usage(const char *progname) {
    pr_error("Usage: %s [options] <input-elf> <output-elf>\n", progname);
    pr_error("Options:\n");
    pr_error("  -d: Enable debug output\n");
    pr_error("  -n: Do not adjust debug sections\n");
    pr_error("  -p: Disable padding of the output file\n");
    exit(EXIT_FAILURE);
}

static void usage(const char *progname) {
    pr_error("Usage: %s [options] <input-elf> <output-elf>\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    uint32_t flags = FLAG_DEBUG_UPDATE|FLAG_FILE_PADDING;
    int r = -1;
    int opt;

    while ((opt = getopt(argc, argv, "dpnh")) != -1) {
        switch (opt) {
            case 'd':
                debug = 1;
                break;
            case 'n':
                flags &= ~FLAG_DEBUG_UPDATE;
                break;
            case 'p':
                flags &= ~FLAG_FILE_PADDING;
                break;
            case 'h':
                detailed_usage(argv[0]);
                break;
            default:
                usage(argv[0]);
        }
    }

    if (argc - optind != 2) {
        usage(argv[0]);
    }

    const char *input_file = argv[optind];
    const char *output_file = argv[optind + 1];

    // Add ".tmp" to the output file name
    char tmp_file[PATH_MAX];
    r = snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", output_file);
    if (r < 0 || r >= (int)sizeof(tmp_file)) {
        pr_error("Output file name too long\n");
        exit(EXIT_FAILURE);
    }

    if (binary_copy(input_file, tmp_file)) {
        pr_error("Failed to copy input file '%s'\n", input_file);
        exit(EXIT_FAILURE);
    }

    r = process_elf(tmp_file, flags);
    if (r != 0) {
        pr_error("Failed to process ELF file\n");
        // Delete the temporary file
        unlink(tmp_file);
        exit(EXIT_FAILURE);
    }

    // Rename the temporary file to the output file
    if (rename(tmp_file, output_file) < 0) {
        perror("rename");
        exit(EXIT_FAILURE);
    }

    return 0;
}