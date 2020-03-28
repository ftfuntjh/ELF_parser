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
    } while (0)

#define ASSIGN_DEFAULT(table, name, type)                                      \
    ASSIGN_TYPE(table, name, offset, type, buffer, buffer_len)

#define ASSIGN_EHDR_DEFAULT(name, type) ASSIGN_DEFAULT(ehdr, name, type)

#define ASSIGN_PHDR_DEFAULT(name, type) ASSIGN_DEFAULT(phdr, name, type)

#define ASSIGN_SHDR_DEFAULT(name, type) ASSIGN_DEFAULT(shdr, name, type)

#define READ_PROPERTY(table, filed, map)                                       \
    map[table->filed >= CH_ARR_CNT(map) ? CH_ARR_CNT(map) - 1 : table->filed]

#define READ_EHDR_PROPERTY(filed, map) READ_PROPERTY(ehdr, filed, map)

#define READ_PHDR_PROPRETY(field, map) READ_PROPERTY(phdr, field, map)

#define READ_SHDR_PROPERTY(field, map) READ_PROPERTY(shdr, filed, map)

static int read_shdr(int fd, Elf64_Shdr*shdr_list,Elf64_Ehdr *ehdr){
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

    return 0;
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
            ehdr->e_phentsize,
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

int main(int argc, char *argv[])
{
    char buffer[512] = {0};
    int fd;
    off_t file_size;
    ssize_t read_size;
    Elf64_Ehdr elf_header;
    Elf64_Shdr *section_headers;
    Elf64_Phdr *program_headers;

    if (argc < 2) {
        fprintf(stderr, "%s Usage: %s filename\n", argv[0], argv[0]);
        return 0;
    }

    fd = open_elf(argv[1]);
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
    print_elf64_header(&elf_header);

    if (elf_header.e_shnum > 0) {
        section_headers =
            (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum);
        read_shdr(fd, section_headers, &elf_header);
    }

    if (elf_header.e_phnum > 0) {
        program_headers =
            (Elf64_Phdr *)malloc(sizeof(Elf64_Phdr) * elf_header.e_phnum);
        read_phdr(fd, program_headers, &elf_header);
    }

    close(fd);
    return 0;
}

