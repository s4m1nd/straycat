#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <binary> <function_name>\n", argv[0]);
        return 1;
    }

    const char *binary = argv[1];
    const char *function = argv[2];

    int fd = open(binary, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)map + ehdr->e_shoff);

    Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *strtab = (const char *)map + sh_strtab->sh_offset;

    Elf64_Shdr *dynsym = NULL;
    Elf64_Shdr *dynstr = NULL;
    Elf64_Shdr *rela_plt = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = strtab + shdr[i].sh_name;
        if (strcmp(name, ".dynsym") == 0) {
            dynsym = &shdr[i];
        } else if (strcmp(name, ".dynstr") == 0) {
            dynstr = &shdr[i];
        } else if (strcmp(name, ".rela.plt") == 0) {
            rela_plt = &shdr[i];
        }
    }

    if (!dynsym || !dynstr || !rela_plt) {
        fprintf(stderr, "Could not find required sections\n");
        munmap(map, st.st_size);
        close(fd);
        return 1;
    }

    const char *dynstr_table = (const char *)map + dynstr->sh_offset;
    Elf64_Sym *sym_table = (Elf64_Sym *)((char *)map + dynsym->sh_offset);
    int sym_count = dynsym->sh_size / dynsym->sh_entsize;

    int func_idx = -1;
    for (int i = 0; i < sym_count; i++) {
        const char *sym_name = dynstr_table + sym_table[i].st_name;
        if (strcmp(sym_name, function) == 0) {
            func_idx = i;
            break;
        }
    }

    if (func_idx == -1) {
        fprintf(stderr, "Function '%s' not found\n", function);
        munmap(map, st.st_size);
        close(fd);
        return 1;
    }

    Elf64_Rela *rela = (Elf64_Rela *)((char *)map + rela_plt->sh_offset);
    int rela_count = rela_plt->sh_size / rela_plt->sh_entsize;

    for (int i = 0; i < rela_count; i++) {
        if (ELF64_R_SYM(rela[i].r_info) == func_idx) {
            printf("0x%lx\n", rela[i].r_offset);
            munmap(map, st.st_size);
            close(fd);
            return 0;
        }
    }

    fprintf(stderr, "GOT entry for '%s' not found\n", function);
    munmap(map, st.st_size);
    close(fd);
    return 1;
}
