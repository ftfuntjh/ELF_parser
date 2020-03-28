#ifndef ELF_DEF_H
#define ELF_DEF_H
extern const char* E_OBJ_TYPE_MAP[6];
extern const char* E_ELF_VERSION_MAP[3];
extern const char* E_MACHINE_MAP[102];
extern const char* E_CLASS_MAP[4];
extern const char* E_DATA_MAP[4];

#define EI_NIDENT 16

#include <stdint.h>

typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Addr;
typedef uint8_t Elf32_Off;

typedef uint64_t Elf64_Addr;
typedef uint16_t Elf64_Half;
typedef uint64_t Elf64_Off;
typedef int32_t Elf64_Sword;
typedef int64_t Elf64_Sxword;
typedef int32_t Elf64_Word;
typedef int64_t Elf64_Lword;
typedef uint64_t Elf64_Xword;
typedef struct
{
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
} Elf32_Ehdr;

/* ELF header */

typedef struct
{
    unsigned char e_ident[EI_NIDENT]; /* File identification. */
    Elf64_Half e_type;                /* File type. */
    Elf64_Half e_machine;             /* Machine architecture. */
    Elf64_Word e_version;             /* ELF format version. */
    Elf64_Addr e_entry;               /* Entry point. */
    Elf64_Off e_phoff;                /* Program header file offset. */
    Elf64_Off e_shoff;                /* Section header file offset. */
    Elf64_Word e_flags;               /* Architecture-specific flags. */
    Elf64_Half e_ehsize;              /* Size of ELF header in bytes. */
    Elf64_Half e_phentsize;           /* Size of program header entry. */
    Elf64_Half e_phnum;               /* Number of program header entries. */
    Elf64_Half e_shentsize;           /* Size of section header entry. */
    Elf64_Half e_shnum;               /* Number of section header entries. */
    Elf64_Half e_shstrndx;            /* Section name strings section. */
} Elf64_Ehdr;

/* Program header */

typedef struct elf64_phdr
{
    Elf64_Word p_type;
    Elf64_Word p_flags;
    Elf64_Off p_offset;
    Elf64_Addr p_vaddr;
    Elf64_Addr p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;

} Elf64_Phdr;

/* Section header */

typedef struct elf64_shdr
{
    Elf64_Word sh_name;
    Elf64_Word sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word sh_link;
    Elf64_Word sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;

} Elf64_Shdr;

#define ELF32_HEADER_SIZE 30
#define ELF64_HEADER_SIZE 38

#define EM_NONE 0x00        // No machine
#define EM_M32 0x01         // AT&T WE 32100
#define EM_SPARC 0x02       // SPARC
#define EM_386 0x03         // Intel Architecute
#define EM_68K 0x04         // Motorola 68000
#define EM_88K 0x05         // Motorola 88000
#define EM_860 0x07         // Intel 80860
#define EM_MIPS 0x08        // MIPS RS3000 Big-Endian
#define EM_MIPS_RS4_BE 0x10 // MIPS RS4000 Big-Endian
// 0xa -0x10 RESERVED 11-16 Reserved for future use

#define ET_NONE 0
#define ET_REL 1
#define ET_EXEC 2
#define ET_DYN 3
#define ET_CORE 4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff

#define EV_NONE 0x00    // Invalid version
#define EV_CURRENT 0x01 // Current version

#define EI_MAGN(EI, N) EI[N]
#define EI_MAG0(EI) EI_MAGN(EI, 0)
#define EI_MAG1(EI) EI_MAGN(EI, 1)
#define EI_MAG2(EI) EI_MAGN(EI, 2)
#define EI_MAG3(EI) EI_MAGN(EI, 3)
#define EI_CLASS(EI) EI_MAGN(EI, 4)
#define EI_DATA(EI) EI_MAGN(EI, 5)
#define EI_VERSION(EI) EI_MAGN(EI, 6)
#define EI_PAD(EI) EI_MAGN(EI, 7)
#define EI_MAG8(EI) EI_MAGN(EI, 8)
#define EI_MAG9(EI) EI_MAGN(EI, 9)
#define EI_MAG10(EI) EI_MAGN(EI, 10)
#define EI_MAG11(EI) EI_MAGN(EI, 11)
#define EI_MAG12(EI) EI_MAGN(EI, 12)
#define EI_MAG13(EI) EI_MAGN(EI, 13)
#define EI_MAG14(EI) EI_MAGN(EI, 14)
#define EI_NIDENTSIZE(EI) EI_MAGN(EI, 15)

#define ELFMAG0 0x7f // magic number
#define ELFMAG1 '\E'
#define ELFMAG2 '\L'
#define ELFMAG3 '\F'

#define ELFCLASSNONE 0x00 // Invalid class
#define ELFCLASS32 0x01   // 32-bit objects
#define ELFCLASS64 0x02   // 64-bit objects

#define ELFDATANONE 0x00 // Invalid data encoding
#define ELFDATA2LSB 0x01
#define ELFDATA2MSB 0x02

#define SHN_UNDEF 0x00A
/* This value marks an undefined, missing, irrelevant, or otherwise */
/* meaningless section reference. For example, a symbol "defined" */
/* relative to section number SHN_UNDEF is an undefined symbol. */

typedef struct
{
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
} Elf32_Shdr;

#define SHT_NULL 0x00
#define SHT_PROGBITS 0x01
#define SHT_SYMTAB 0x02
#define SHT_STRTAB 0x03
#define SHT_RELA 0x04
#define SHT_HASH 0x05
#define SHT_DYNAMIC 0x06
#define SHT_NOTE 0x07
#define SHT_NOBITS 0x08
#define SHT_REL 0x09
#define SHT_SHLIB 0x10
#define SHT_DYNSYM 0x11
#define SHT_LOPROC 0x70000000
#define SHT_HIPROC 0x7fffffff
#define SHT_LOUSER 0x80000000
#define SHT_HIUSER 0xffffffff

#endif // ELF_DEF_H
