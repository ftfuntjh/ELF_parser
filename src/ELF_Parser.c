#include "ELF_Def.h"
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ARRAY_ELEMENT_SIZE(ARRAY, ELEMENT) (sizeof(ARRAY) / sizeof(ELEMENT))
#define CH_ARR_CNT(ARRAY) ARRAY_ELEMENT_SIZE(ARRAY, const char *)
#define ASSIGN_TYPE(header, name, offset, type, buffer, buffer_len)            \
    do {                                                                       \
        type type_v_ = 0;                                                      \
        if ((offset) + sizeof(type) > (buffer_len))                            \
            return -1;                                                         \
                                                                               \
        for (int i = 0; i < sizeof(type); i++) {                               \
            type_v_ |=                                                         \
                (type)(((unsigned char)(buffer[offset + i])) << (i * 8));      \
        }                                                                      \
        header->name = type_v_;                                                \
        offset += sizeof(type);                                                \
                                                                               \
    } while (0)

#define ASSIGN_DEFAULT(table, name, type)                                      \
    ASSIGN_TYPE(table, name, offset, type, buffer, buffer_len)

#define ASSIGN_EHDR_DEFAULT(name, type) ASSIGN_DEFAULT(ehdr, name, type)

#define ASSIGN_PHDR_DEFAULT(name, type) ASSIGN_DEFAULT(phdr, name, type)

#define ASSIGN_SHDR_DEFAULT(name, type) ASSIGN_DEFAULT(shdr, name, type)

#define ASSIGN_SYM_DEFAULT(name, type) ASSIGN_DEFAULT(sym, name, type)

#define READ_PROPERTY(table, field, map)                                       \
    map[table->field >= CH_ARR_CNT(map) ? CH_ARR_CNT(map) - 1 : table->field]

#define READ_EHDR_PROPERTY(field, map) READ_PROPERTY(ehdr, field, map)

#define READ_PHDR_PROPRETY(field, map) READ_PROPERTY(phdr, field, map)

#define READ_SHDR_PROPERTY(field, map) READ_PROPERTY(shdr, field, map)

#define READ_SYM_PROPERTY(field, map) READ_PROPERTY(sym, field, map)

static void print_sym64(Elf64_Sym *sym_list, size_t sym_count, char *strtab)
{
    if (sym_list == NULL) {
        fprintf(stderr, "print_sym64: sym_list is NULL\n");
        return;
    }

    if (strtab == NULL) {
        fprintf(stderr, "print_sym64: strtab is NULL");
    }

    printf("sym_count is %lu\n", sym_count);

    for (int i = 1; i < sym_count; i++) {
        Elf64_Sym *sym = sym_list + i;
        fprintf(stdout,
                "  %-36s%s\n",
                "String table index:",
                strtab + sym->st_name);

        fprintf(stdout, "  %-36s%p\n", "Symbol value:", (void *)sym->st_value);

        fprintf(stdout, "  %-36s%lu\n", "Symbol size:", sym->st_size);

        if (ELF64_ST_BIND(i) == STB_LOCAL) {
            fprintf(stdout, "  %-36s%-36s\n", "Symbol bind type:", "STB_LOCAL");
        } else if (ELF64_ST_BIND(i) == STB_GLOBAL) {
            fprintf(
                stdout, "  %-36s%-36s\n", "Symbol bind type:", "STB_GLOBAL");
        } else if (ELF64_ST_BIND(i) == STB_WEAK) {
            fprintf(stdout, "  %-36s%-36s\n", "Symbol bind type:", "STB_WEAK");
        }
        fprintf(stdout, "\n\n");
    }
}

static int read_strtab(int fd, Elf64_Shdr *str_ehdr, char **buffer)
{
    if (fd < 0) {
        fprintf(stderr, "read_strtab: invalid fd %d \n", fd);
        return -1;
    }

    if (str_ehdr == NULL) {
        fprintf(stderr, "read_strtabl: str_ehdr is NULL\n");
        return -1;
    }

    lseek(fd, str_ehdr->sh_offset, SEEK_SET);

    *buffer = (char *)malloc(str_ehdr->sh_size);

    if (read(fd, *buffer, str_ehdr->sh_size) < 0) {
        fprintf(stderr,
                "read_strtab: read fd %d failed,errno=%d, 'msg'=%s\n",
                fd,
                errno,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int
read_strsn(int fd, Elf64_Shdr *sstr, char **buffer, size_t *buffer_len)
{
    if (fd < 0) {
        fprintf(stderr, "read_sstr_shdr: fd %d invalid.\n", fd);
        return -1;
    }

    lseek(fd, sstr->sh_offset, SEEK_SET);

    *buffer_len = sstr->sh_size;
    *buffer = (char *)malloc(sstr->sh_size);
    if (read(fd, *buffer, sstr->sh_size) < 0) {
        fprintf(stderr,
                "read_phdr read fd %d failed errno=%d msg='%s'\n",
                fd,
                errno,
                strerror(errno));
        free(*buffer);
        *buffer = NULL;
        return -1;
    }

    return 0;
}

static int read_shdr(int fd, Elf64_Shdr *shdr_list, Elf64_Ehdr *ehdr)
{
    size_t buffer_len, file_size, shdr_size;
    char *buffer;

    if (ehdr == NULL) {
        fprintf(stderr, "read_shdr failed,ehdr table is NULL.\n");
        return -1;
    }

    if (fd < 0) {
        fprintf(stderr, "read_shdr failed,fd %d is invalid.\n", fd);
        return -1;
    }

    if (shdr_list == NULL) {
        fprintf(stderr,
                "read_shdr failed,please alloc phdr list mem before call.\n");
        return -1;
    }

    file_size = lseek(fd, 0, SEEK_END);

    if (ehdr->e_shoff < ehdr->e_ehsize || ehdr->e_shoff >= file_size) {
        fprintf(stderr, "e_shoff %lu is invalid.\n", ehdr->e_shoff);
        return -1;
    }

    shdr_size = ehdr->e_shnum * ehdr->e_shentsize;
    buffer_len = shdr_size;
    buffer = (char *)malloc(buffer_len);
    lseek(fd, ehdr->e_shoff, SEEK_SET);

    if (read(fd, buffer, buffer_len) < 0) {
        fprintf(stderr,
                "read_phdr read fd %d failed errno=%d msg='%s'\n",
                fd,
                errno,
                strerror(errno));
        free(buffer);
        return -1;
    }

    size_t offset = 0;
    for (Elf64_Word i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *shdr = shdr_list + i;
        ASSIGN_SHDR_DEFAULT(sh_name, Elf64_Word);

        ASSIGN_SHDR_DEFAULT(sh_type, Elf64_Word);

        ASSIGN_SHDR_DEFAULT(sh_flags, Elf64_Xword);

        ASSIGN_SHDR_DEFAULT(sh_addr, Elf64_Addr);

        ASSIGN_SHDR_DEFAULT(sh_offset, Elf64_Off);

        ASSIGN_SHDR_DEFAULT(sh_size, Elf64_Xword);

        ASSIGN_SHDR_DEFAULT(sh_link, Elf64_Word);

        ASSIGN_SHDR_DEFAULT(sh_info, Elf64_Word);

        ASSIGN_SHDR_DEFAULT(sh_addralign, Elf64_Xword);

        ASSIGN_SHDR_DEFAULT(sh_entsize, Elf64_Xword);
    }

    free(buffer);
    return 0;
}

static int read_phdr(int fd, Elf64_Phdr *phdr_list, Elf64_Ehdr *ehdr)
{
    size_t file_size, phdr_size;
    unsigned char *buffer;
    if (ehdr == NULL) {
        fprintf(stderr, "read_phdr failed,ehdr table is NULL.\n");
        return -1;
    }

    if (fd < 0) {
        fprintf(stderr, "read_phdr failed,fd %d is invalid.\n", fd);
        return -1;
    }

    if (phdr_list == NULL) {
        fprintf(stderr,
                "read_phdr failed,please alloc phdr list mem before call.\n");
        return -1;
    }

    file_size = lseek(fd, 0, SEEK_END);

    if (ehdr->e_phoff < ehdr->e_ehsize || ehdr->e_phoff >= file_size) {
        fprintf(stderr, "e_phoff %lu is invalid.\n", ehdr->e_phoff);
        return -1;
    }

    phdr_size = ehdr->e_phnum * ehdr->e_phentsize;
    lseek(fd, ehdr->e_phoff, SEEK_SET);

    size_t buffer_len = phdr_size;
    buffer = (unsigned char *)malloc(buffer_len);
    if (read(fd, buffer, buffer_len) < 0) {
        fprintf(stderr,
                "read_phdr read fd %d failed errno=%d msg='%s'\n",
                fd,
                errno,
                strerror(errno));
        free(buffer);
        return -1;
    }

    size_t offset = 0;
    for (Elf64_Word i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *phdr = phdr_list + i;

        ASSIGN_PHDR_DEFAULT(p_type, Elf64_Word);

        ASSIGN_PHDR_DEFAULT(p_flags, Elf64_Word);

        ASSIGN_PHDR_DEFAULT(p_offset, Elf64_Off);

        ASSIGN_PHDR_DEFAULT(p_vaddr, Elf64_Addr);

        ASSIGN_PHDR_DEFAULT(p_paddr, Elf64_Addr);

        ASSIGN_PHDR_DEFAULT(p_filesz, Elf64_Xword);

        ASSIGN_PHDR_DEFAULT(p_memsz, Elf64_Xword);

        ASSIGN_PHDR_DEFAULT(p_align, Elf64_Xword);
    }

    free(buffer);
    return 0;
}

static void print_shdr64_headers(int fd,
                                 Elf64_Shdr *shdr_list,
                                 Elf64_Ehdr *ehdr,
                                 char *sstrtab)
{
    char buffer[512] = {0};

    for (Elf64_Word i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *shdr = shdr_list + i;
        fprintf(stdout,
                "  %-36s%d (%s)\n",
                "Section name index:",
                shdr->sh_name,
                &sstrtab[shdr->sh_name]);

        fprintf(stdout,
                "  %-36s%-36s\n",
                "Section type:",
                READ_SHDR_PROPERTY(sh_type, E_SHDR_TYPE_MAP));

        memset(buffer, 0, sizeof(buffer));

        if (0x01 & shdr->sh_flags) {
            strcat(buffer, "SHF_WRITE");
        }

        if (0x2 & shdr->sh_flags) {
            if (buffer[0] != '\0') {
                strcat(buffer, " | ");
            }

            strcat(buffer, "SHF_ALLOC");
        }

        if (0x4 & shdr->sh_flags) {
            if (buffer[0] != '\0') {
                strcat(buffer, " | ");
            }
            strcat(buffer, "SHF_EXECINSTR");
        }

        fprintf(stdout, "  %-36s%-36s\n", "Section flag:", buffer);

        fprintf(
            stdout, "  %-36s%p\n", "Section Address:", (void *)shdr->sh_addr);

        fprintf(stdout,
                "  %-36s%lu %s\n",
                "Section start:",
                shdr->sh_offset,
                "(bytes in file)");

        fprintf(stdout,
                "  %-36s%lu %s\n",
                "Section size:",
                shdr->sh_size,
                "(bytes)");

        fprintf(stdout,
                "  %-36s0x%x\n",
                "Section link information:",
                shdr->sh_link);

        fprintf(stdout, "  %-36s0x%x\n", "Section information:", shdr->sh_info);

        fprintf(stdout,
                "  %-36s0x%lx\n",
                "Section address align:",
                shdr->sh_addralign);

        fprintf(
            stdout, "  %-36s0x%lu\n", "Section entry size:", shdr->sh_entsize);

        fprintf(stdout, "\n\n");
    }
}

static void print_elf64_header(Elf64_Ehdr *ehdr)
{
    fprintf(stdout, "ELF Header:\n");
    fprintf(stdout, "  Magic:  ");

    for (int i = 0; i < EI_NIDENT; i++) {
        fprintf(stdout, " %.2X", ehdr->e_ident[i]);
    }

    fprintf(stdout,
            "\n  %-36s%-36s\n",
            "Class:",
            READ_EHDR_PROPERTY(EI_CLASS(e_ident), E_CLASS_MAP));

    fprintf(stdout,
            "  %-36s%-36s\n",
            "Data:",
            READ_EHDR_PROPERTY(EI_DATA(e_ident), E_DATA_MAP));

    fprintf(stdout,
            "  %-36s%-2d(%s)\n",
            "Version:",
            ehdr->e_version,
            READ_EHDR_PROPERTY(e_version, E_ELF_VERSION_MAP));

    fprintf(stdout,
            "  %-36s%-36s\n",
            "Machine:",
            READ_EHDR_PROPERTY(e_machine, E_MACHINE_MAP));

    fprintf(stdout,
            "  %-36s%-36s\n",
            "Type:",
            READ_EHDR_PROPERTY(e_type, E_OBJ_TYPE_MAP));

    fprintf(stdout,
            "  %-36s%-36p\n",
            "Entry point address:",
            (void *)ehdr->e_entry);

    fprintf(stdout,
            "  %-36s%lu %s\n",
            "Start of program headers:",
            ehdr->e_phoff,
            "(bytes into file)");

    fprintf(stdout,
            "  %-36s%lu %s\n",
            "Start of section headers:",
            (unsigned long)ehdr->e_shoff,
            "(bytes into file)");

    fprintf(stdout, "  %-36s0x%X\n", "Flags:", ehdr->e_flags);

    fprintf(stdout,
            "  %-36s%d %s\n",
            "Size of this header:",
            ehdr->e_ehsize,
            "(bytes)");

    fprintf(stdout,
            "  %-36s%d %s\n",
            "Size of program headers:",
            ehdr->e_phentsize,
            "(bytes)");

    fprintf(stdout, "  %-36s%d\n", "Number of program headers:", ehdr->e_phnum);

    fprintf(stdout,
            "  %-36s%d %s\n",
            "Size of section headers:",
            ehdr->e_shentsize,
            "(bytes)");

    fprintf(stdout, "  %-36s%d\n", "Number of section headers:", ehdr->e_shnum);

    fprintf(stdout,
            "  %-36s%d\n",
            "Section header string table index:",
            ehdr->e_shstrndx);
}

static void print_elf32_header(Elf32_Ehdr *ehdr)
{
    fprintf(stdout, "ELF Header:\n");
    fprintf(stdout, "  Magic:  ");

    for (int i = 0; i < EI_NIDENT; i++) {
        fprintf(stdout, " %.2X", ehdr->e_ident[i]);
    }

    fprintf(stdout,
            "\n  %-36s%-36s\n",
            "Class:",
            READ_EHDR_PROPERTY(EI_CLASS(e_ident), E_CLASS_MAP));

    fprintf(stdout,
            "  %-36s%-36s\n",
            "Data:",
            READ_EHDR_PROPERTY(EI_DATA(e_ident), E_DATA_MAP));

    fprintf(stdout,
            "  %-36s%-2d(%s)\n",
            "Version:",
            ehdr->e_version,
            READ_EHDR_PROPERTY(e_version, E_ELF_VERSION_MAP));

    fprintf(stdout,
            "  %-36s%-36s\n",
            "Machine:",
            READ_EHDR_PROPERTY(e_machine, E_MACHINE_MAP));

    fprintf(stdout,
            "  %-36s%-36s\n",
            "Type:",
            READ_EHDR_PROPERTY(e_type, E_OBJ_TYPE_MAP));

    fprintf(stdout, "  %-36s0x%-34X\n", "Entry point address:", ehdr->e_entry);

    fprintf(stdout,
            "  %-36s%d %s\n",
            "Start of program headers:",
            ehdr->e_phoff,
            "(bytes into file)");

    fprintf(stdout,
            "  %-36s%lu %s\n",
            "Start of section headers:",
            (unsigned long)ehdr->e_shoff,
            "(bytes into file)");

    fprintf(stdout, "  %-36s0x%X\n", "Flags:", ehdr->e_flags);

    fprintf(stdout,
            "  %-36s%d %s\n",
            "Size of this header:",
            ehdr->e_ehsize,
            "(bytes)");

    fprintf(stdout,
            "  %-36s%d %s\n",
            "Size of program headers:",
            ehdr->e_phentsize,
            "(bytes)");

    fprintf(stdout, "  %-36s%d\n", "Number of program headers:", ehdr->e_phnum);

    fprintf(stdout,
            "  %-36s%d %s\n",
            "Size of section headers:",
            ehdr->e_phentsize,
            "(bytes)");

    fprintf(stdout, "  %-36s%d\n", "Number of section headers:", ehdr->e_phnum);

    fprintf(stdout,
            "  %-36s%d\n",
            "Section header string table index:",
            ehdr->e_shstrndx);
}

int open_elf(const char *file_path)
{
    int ret = open(file_path, O_RDONLY);
    if (ret < 0) {
        fprintf(stderr,
                "open file '%s' failed errno=%d msg='%s'.\n",
                file_path,
                errno,
                strerror(errno));
    }
    return ret;
}

int read_ehdr(Elf64_Ehdr *ehdr, char *buffer, ssize_t buffer_len)
{
    int offset = 0;
    unsigned char *e_ident;
    if (offset + EI_NIDENT * sizeof(unsigned char) > buffer_len)
        return -1;
    e_ident = &ehdr->e_ident[0];
    for (int i = 0; i < EI_NIDENT * sizeof(unsigned char); i++) {
        e_ident[i] = buffer[offset + i];
    }
    offset += EI_NIDENT * sizeof(unsigned char);

    ASSIGN_EHDR_DEFAULT(e_type, Elf64_Half);

    ASSIGN_EHDR_DEFAULT(e_machine, Elf64_Half);

    ASSIGN_EHDR_DEFAULT(e_version, Elf64_Word);

    ASSIGN_EHDR_DEFAULT(e_entry, Elf64_Addr);

    ASSIGN_EHDR_DEFAULT(e_phoff, Elf64_Off);

    ASSIGN_EHDR_DEFAULT(e_shoff, Elf64_Off);

    ASSIGN_EHDR_DEFAULT(e_flags, Elf64_Word);

    ASSIGN_EHDR_DEFAULT(e_ehsize, Elf64_Half);

    ASSIGN_EHDR_DEFAULT(e_phentsize, Elf64_Half);

    ASSIGN_EHDR_DEFAULT(e_phnum, Elf64_Half);

    ASSIGN_EHDR_DEFAULT(e_shentsize, Elf64_Half);

    ASSIGN_EHDR_DEFAULT(e_shnum, Elf64_Half);

    ASSIGN_EHDR_DEFAULT(e_shstrndx, Elf64_Half);

    return 0;
}

int read_sym(int fd, Elf64_Shdr *sym_shdr, Elf64_Sym **ent_list)
{
    if (sym_shdr == NULL) {
        fprintf(stdout, "read_dynamic_symbols: empty symbol header.\n");
        return -1;
    }

    if (fd < 0) {
        fprintf(stderr, "read_dynamc_symbols: invalid fd %d \n", fd);
        return -1;
    }

    size_t buffer_len = sym_shdr->sh_size;
    Elf64_Xword sym_cnt = sym_shdr->sh_size / sym_shdr->sh_entsize;
    Elf64_Off sh_offset = sym_shdr->sh_offset;

    char *buffer = malloc(buffer_len);

    printf("buffer_len= %lu, sym_cnt= %lu\n", buffer_len, sym_cnt);
    lseek(fd, sh_offset, SEEK_SET);

    if (read(fd, buffer, buffer_len) < 0) {
        fprintf(stderr, "read_dynamic_symbols: read fd %d failed\n", fd);
        return -1;
    }

    Elf64_Sym *ptr = (Elf64_Sym *)malloc(sizeof(Elf64_Sym) * sym_cnt);
    memset(ptr, 0, sizeof(Elf64_Sym) * sym_cnt);

    *ent_list = ptr;

    size_t offset = 0;
    for (int i = 1; i < sym_cnt; i++) {
        Elf64_Sym *sym = ptr;
        ASSIGN_SYM_DEFAULT(st_name, Elf64_Word);

        ASSIGN_SYM_DEFAULT(st_info, unsigned char);

        ASSIGN_SYM_DEFAULT(st_other, unsigned char);

        ASSIGN_SYM_DEFAULT(st_shndx, Elf64_Half);

        ASSIGN_SYM_DEFAULT(st_value, Elf64_Addr);

        ASSIGN_SYM_DEFAULT(st_size, Elf64_Addr);

        ptr++;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    char buffer[512] = {0};
    int fd;
    off_t file_size;
    ssize_t read_size;
    size_t symtab_size = 0, sh_str_size = 0;
    char *symtab_name = NULL, *sh_str_table = NULL;
    Elf64_Ehdr elf_header;
    Elf64_Shdr *section_headers;
    Elf64_Phdr *program_headers;
    Elf64_Sym *symbol_tables = NULL;

    if (argc < 3) {
        fprintf(stderr, "%s Usage: %s {-h,-s,-p} filename\n", argv[0], argv[0]);
        return 0;
    }

    fd = open_elf(argv[2]);
    if (fd < 0) {
        return -1;
    }

    file_size = lseek(fd, 0, SEEK_END);
    if (file_size < ELF64_HEADER_SIZE) {
        fprintf(stderr,
                "file size %ld less than ELF Header size %d.\n",
                file_size,
                ELF64_HEADER_SIZE);
        return -1;
    }
    lseek(fd, 0, SEEK_SET);
    read_size = read(fd, buffer, sizeof(buffer));
    if (read_ehdr(&elf_header, buffer, read_size) < 0) {
        fprintf(stderr, "read ehdr failed.\n");
        return -1;
    }
    if (elf_header.e_shnum > 0) {
        section_headers =
            (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum);
        if (read_shdr(fd, section_headers, &elf_header) < 0) {
            printf("read shdr failed.\n");
            return -1;
        }

        Elf64_Shdr *strhdr = section_headers + elf_header.e_shstrndx;
        if (read_strsn(fd, strhdr, &sh_str_table, &sh_str_size) < 0) {
            return -1;
        }
    }

    if (elf_header.e_phnum > 0) {
        program_headers =
            (Elf64_Phdr *)malloc(sizeof(Elf64_Phdr) * elf_header.e_phnum);
        read_phdr(fd, program_headers, &elf_header);
    }

    Elf64_Shdr *str_ehdr = NULL;
    Elf64_Shdr *sym_ehdr = NULL;
    if (section_headers != NULL) {
        for (int i = 0; i < elf_header.e_shnum; i++) {
            Elf64_Shdr *shdr = section_headers + i;
            char *section_name = sh_str_table + shdr->sh_name;
            if (*section_name == '\0')
                continue;
            if (strcmp(section_name, ".symtab") == 0) {
                sym_ehdr = section_headers + i;
            } else if (strcmp(section_name, ".strtab") == 0) {
                str_ehdr = section_headers + i;
            }
        }
    }

    if (str_ehdr != NULL) {
        read_strtab(fd, str_ehdr, &symtab_name);
    }

    if (sym_ehdr != NULL && symtab_name != NULL) {
        read_sym(fd, sym_ehdr, &symbol_tables);
    }

    if (strcmp(argv[1], "-h") == 0) {
        print_elf64_header(&elf_header);
    } else if (strcmp(argv[1], "-s") == 0) {
        print_shdr64_headers(fd, section_headers, &elf_header, sh_str_table);
    } else if (strcmp(argv[1], "-t") == 0) {
        print_sym64(symbol_tables,
                    sym_ehdr->sh_size / sym_ehdr->sh_entsize,
                    symtab_name);
    }

    free(symtab_name);
    free(section_headers);
    free(program_headers);
    close(fd);
    return 0;
}

