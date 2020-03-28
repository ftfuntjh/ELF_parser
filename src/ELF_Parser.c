#include "ELF_Def.h"
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
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

#define ASSIGN_DEFAULT(name, type)                                             \
    ASSIGN_TYPE(ehdr, name, offset, type, buffer, buffer_len)

#define READ_PROPERTY(filed, map)                                              \
    map[ehdr->filed >= CH_ARR_CNT(map) ? CH_ARR_CNT(map) - 1 : ehdr->filed]

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
            READ_PROPERTY(EI_CLASS(e_ident), E_CLASS_MAP));

    fprintf(stdout,
            "  %-36s%-36s\n",
            "Data:",
            READ_PROPERTY(EI_DATA(e_ident), E_DATA_MAP));

    fprintf(stdout,
            "  %-36s%-2d(%s)\n",
            "Version:",
            ehdr->e_version,
            READ_PROPERTY(e_version, E_ELF_VERSION_MAP));

    fprintf(stdout,
            "  %-36s%-36s\n",
            "Machine:",
            READ_PROPERTY(e_machine, E_MACHINE_MAP));

    fprintf(stdout,
            "  %-36s%-36s\n",
            "Type:",
            READ_PROPERTY(e_type, E_OBJ_TYPE_MAP));

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

    fprintf(stdout, "  %-36s%d\n", "Number of section headers:", ehdr->e_phnum);

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
    fprintf(stdout, "\n   %-40s%-40s\n", "Class:", "");

    fprintf(stdout,
            "   %-40s%-3d (%s)\n",
            "Version:",
            ehdr->e_version,
            E_ELF_VERSION_MAP[ehdr->e_version >= CH_ARR_CNT(E_ELF_VERSION_MAP)
                                  ? CH_ARR_CNT(E_ELF_VERSION_MAP) - 1
                                  : ehdr->e_version]);
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

    ASSIGN_DEFAULT(e_type, Elf64_Half);

    ASSIGN_DEFAULT(e_machine, Elf64_Half);

    ASSIGN_DEFAULT(e_version, Elf64_Word);

    ASSIGN_DEFAULT(e_entry, Elf64_Addr);

    ASSIGN_DEFAULT(e_phoff, Elf64_Off);

    ASSIGN_DEFAULT(e_shoff, Elf64_Off);

    ASSIGN_DEFAULT(e_flags, Elf64_Word);

    ASSIGN_DEFAULT(e_ehsize, Elf64_Half);

    ASSIGN_DEFAULT(e_phentsize, Elf64_Half);

    ASSIGN_DEFAULT(e_phnum, Elf64_Half);

    ASSIGN_DEFAULT(e_shentsize, Elf64_Half);

    ASSIGN_DEFAULT(e_shnum, Elf64_Half);

    ASSIGN_DEFAULT(e_shstrndx, Elf64_Half);

    return 0;
}

int main(int argc, char *argv[])
{
    char buffer[512] = {0};
    int fd;
    off_t file_size;
    ssize_t read_size;
    Elf64_Ehdr elf_header;
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

    close(fd);
    return 0;
}

