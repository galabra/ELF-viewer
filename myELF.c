#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "sys/stat.h"
#include <fcntl.h>
#include <unistd.h>
#include "elf.h"

int Currentfd = -1;
void* map_start;
struct stat fd_stat;
int isTesting = 0;

struct menu_func{
    char* name;
    int (*func)();
};

void freeMemory() {
    close(Currentfd);
    munmap(map_start, fd_stat.st_size);
}

int getFileSize() {
    if(fstat(Currentfd, &fd_stat) != 0) {
        perror("Stat failed");
        freeMemory();
        return -1;
    }
    return fd_stat.st_size;
}

int isELF(Elf64_Ehdr* header) {
    if(header->e_ident[1] == 'E' && header->e_ident[2] == 'L' && header->e_ident[3] == 'F') {
        return 1;
    }
    return 0;
}

int examine() {
    int fileSize;
    char* fileName;
    
    if(isTesting) {
        fileName = "test";
    }
    else {
        printf("Please insert <filename> to examine:\t");
        char input[100];
        fgets(input, sizeof(input), stdin);
        input[strlen(input)-1] = '\0';
        fileName = strdup(input);
    } 
    
    if(Currentfd != -1) {
        close(Currentfd);
    }
    if( (Currentfd = open(fileName, O_RDONLY)) < 0 ) {
        perror("Error in open");
        freeMemory();
        return 0;
    }
    
    if( (fileSize = getFileSize()) < 0 ) {
        perror("Error in file size");
        freeMemory();
        return 0;
    }
    
    map_start = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, Currentfd, 0);
    Elf64_Ehdr* header = (Elf64_Ehdr *) map_start;
    
    if(!isELF(header)) {
        Currentfd = -1;
        perror("File isn't in ELF format");
        freeMemory();
        return 0;
    }
    
    printf("ELF Header:\n");
    printf("  1. Magic:\t\t\t\t%c %c %c\n",                              header->e_ident[1], header->e_ident[2], header->e_ident[3]);
    printf("  2. Data\t\t\t\t%s\n",                                      (header->e_ident[5]==1 ? "Little Endian" : "Big Endian"));
    printf("  3. Entry point address:\t\t%x\n",                          (unsigned int) header->e_entry);
    printf("  4. Start of section headers:\t\t%d (bytes into file)\n",   (unsigned int) header->e_shoff);
    printf("  5. Number of section headers:\t\t%d\n",                    (unsigned int) header->e_shnum);
    printf("  6. Size of section headers:\t\t%d (bytes)\n",              (unsigned int) header->e_shentsize);
    printf("  7. Start of program headers:\t\t%d (bytes into file)\n",   (unsigned int) header->e_phoff);
    printf("  8. Number of program headers:\t\t%d\n",                    (unsigned int) header->e_phnum);
    printf("  9. Size of program headers:\t\t%d (bytes)\n",              (unsigned int) header->e_phentsize);
    
    return 0;
};

void tab(char* txt) {
    if(strlen(txt) < 20)
        for(int i=0; i<20-strlen(txt); i++)
            printf(" ");
    else
        putchar(' ');
}

int printSectionNames() {
    if(Currentfd == -1) {
        perror("No valid file is open");
        return(0);
    }
    printf("Section Headers:\n  [Nr] Name                Address           Offset    Size              Type\n");
    
    Elf64_Ehdr* header = (Elf64_Ehdr*) map_start;
    Elf64_Shdr* stringTable = (Elf64_Shdr*) (map_start + header->e_shoff + header->e_shstrndx*sizeof(Elf64_Shdr));
    int numOfSections = header->e_shnum;
    
    for(int i=0; i<numOfSections; i++) {
        Elf64_Shdr* sHeader = (Elf64_Shdr*) (map_start + header->e_shoff + i*sizeof(Elf64_Shdr));
        
        char* section_name = map_start + stringTable->sh_offset + sHeader->sh_name;
        int section_address = (unsigned int) sHeader->sh_addr;
        int section_offset = (unsigned int) sHeader->sh_offset;
        int section_size = (unsigned int) sHeader->sh_size;
        int section_type = (unsigned int) sHeader->sh_type;
    
        printf("  [%02d] %s", i, section_name);
        tab(section_name);
        printf("%016x  ", section_address);
        printf("%08x  ", section_offset);
        printf("%016x  ", section_size);
        printf("%016x", section_type);
        putchar('\n');
    }
    
};

int printSymbols() {
    if(Currentfd == -1) {
        perror("No valid file is open");
        return(0);
    }
    
    Elf64_Ehdr* header = (Elf64_Ehdr *) map_start;
    Elf64_Shdr* stringTable = (Elf64_Shdr*) (map_start + header->e_shoff + header->e_shstrndx*sizeof(Elf64_Shdr));
    int numOfSections = header->e_shnum;
    Elf64_Shdr* symbolTable_sectionHeader;
    Elf64_Shdr* symbolsStringTabler;
    
    for(int i=0; i<numOfSections; i++) {
        Elf64_Shdr* section = (Elf64_Shdr*) (map_start + header->e_shoff + i*sizeof(Elf64_Shdr));
        char* section_name = map_start + stringTable->sh_offset + section->sh_name;
        
        if(strcmp(section_name, ".strtab") == 0) {
            symbolsStringTabler = section;
            break;
        }
    }
    
    for(int i=0; i<numOfSections; i++) {
        Elf64_Shdr* section = (Elf64_Shdr*) (map_start + header->e_shoff + i*sizeof(Elf64_Shdr));
        if(section->sh_type == 2) {
            symbolTable_sectionHeader = section;
            break;
        }
    }
    
    printf("Symbols:\n  [Nr] Value             Index  SectionName         SymbolName\n");
    
    int numOfSymbols = symbolTable_sectionHeader->sh_size / sizeof(Elf64_Sym);
    for(int i=0; i<numOfSymbols; i++) {
        Elf64_Sym* symbolTable = (Elf64_Sym*) (map_start + symbolTable_sectionHeader->sh_offset + i*sizeof(Elf64_Sym));
        char* section_name;
        
        int symbol_value  = (unsigned int) symbolTable->st_value;
        int symbol_index  = (unsigned int) symbolTable->st_shndx;
        int section_index = (unsigned int) symbolTable->st_shndx;
        if(symbol_index == 0xfff1) {
            section_name = "ABS";
        }
        else {    
            Elf64_Shdr* sHeader = (Elf64_Shdr*) (map_start + header->e_shoff + symbol_index*sizeof(Elf64_Shdr));
            section_name = map_start + stringTable->sh_offset + sHeader->sh_name;
        }
        
        char* symbol_name  = map_start + symbolsStringTabler->sh_offset + symbolTable->st_name;
        
        
        printf("  [%02d] %016x  ", i, symbol_value);
        
        if(symbol_index == 0xfff1)
            printf("  ABS  ");
        else if(symbol_index < 10)
            printf("    %d  ", symbol_index);
        else if(symbol_index < 100)
            printf("   %d  ", symbol_index);
        else
            printf("  %d  ", symbol_index);
        
        printf("%s", section_name);
        tab(section_name);
        printf("%s", symbol_name);
        
        putchar('\n');
    }
    
    
};

int quit() {
    freeMemory();
    exit(0);
};

struct menu_func menu[] = {{"Examine ELF File", examine}, {"Print Section Names", printSectionNames}, {"Print Symbols", printSymbols}, {"Quit", quit}, {NULL, NULL}};

int printMenu() {
    int menuSizeByOptions = (sizeof(menu) / sizeof(struct menu_func)) - 1;
    
    printf("Choose action:\n");
    for(int i=0; i<menuSizeByOptions; i++) {
        printf("%d-%s\n", i+1, menu[i].name);
    }
    
    return menuSizeByOptions;
}

int main (int argc , char* argv[]) {
    char input[100];
    int menuSizeByOptions = printMenu();

    while(1) {
        printf("> ");
        fgets(input, sizeof(input), stdin);
        int option = atoi(input) - 1;
        if(option >= 0 && option <= menuSizeByOptions-1) {
            menu[option].func();
        }
    }

    return 0;
}
