// easyvm_structs.h - Struct definitions for easyvm binary

#include <stdint.h>

typedef struct VMRegisters VMRegisters;
typedef struct VMMemory VMMemory;
typedef struct VMProgramState VMProgramState;
typedef struct VMContext VMContext;
typedef struct LabelEntry LabelEntry;
typedef struct LabelTable LabelTable;
typedef struct UserSession UserSession;
typedef struct PacketContext PacketContext;
typedef struct TokenLine TokenLine;
typedef struct Tokenizer Tokenizer;

struct VMRegisters {
    uint32_t cmp_flags;         // +0x00: Comparison flags
    uint32_t mod_result;        // +0x04: MOD result
    uint64_t reserved[5];       // +0x08-0x2F
    void*    esp;               // +0x30: Stack pointer
    void*    stack_base;        // +0x38: Stack base
    uint32_t eip;               // +0x40: Instruction pointer
    uint32_t pad;               // +0x44
};

struct VMMemory {
    uint32_t flags;             // +0x00
    uint32_t pad1;              // +0x04
    void*    data;              // +0x08: Memory buffer
    int32_t  size;              // +0x10: Memory size
    uint32_t pad2;              // +0x14
    VMRegisters* regs;          // +0x18: Registers
};

struct LabelEntry {
    char*       name;           // +0x00: Label name
    int32_t     address;        // +0x08: Address
    uint32_t    pad;            // +0x0C
    char*       extra;          // +0x10: Extra data
    LabelEntry* next;           // +0x18: Next in chain
};

struct LabelTable {
    uint32_t     count;         // +0x00
    uint32_t     capacity;      // +0x04
    LabelEntry** buckets;       // +0x08
};

struct VMProgramState {
    uint32_t    start_ip;       // +0x00: Start IP
    uint32_t    instr_count;    // +0x04: Instruction count
    int32_t*    opcodes;        // +0x08: Opcode array
    void*       reserved1;      // +0x10
    void**      operands;       // +0x18: Operand array
    int32_t     operand_count;  // +0x20
    void*       reserved2;      // +0x28
    LabelTable* labels;         // +0x30: Label table
};

struct VMContext {
    VMProgramState* program;    // +0x00
    VMMemory*       memory;     // +0x08
};

struct UserSession {
    int32_t  username_len;      // +0x000
    char     username[0x180];   // +0x004 (384 bytes)
    int32_t  password_len;      // +0x184
    char     password[0x180];   // +0x188 (384 bytes)
    void*    encode_func;       // +0x308
    uint64_t session_id;        // +0x310
};

struct PacketContext {
    uint32_t     version;       // +0x00
    uint32_t     opcode;        // +0x04
    uint32_t     reserved1;     // +0x08
    uint32_t     data_length;   // +0x0C
    uint64_t     reserved2;     // +0x10
    UserSession* session;       // +0x18
    uint32_t     is_logged_in;  // +0x20
    uint32_t     pad;           // +0x24
};

struct TokenLine {
    char* token0;               // +0x00: label/opcode
    char* token1;               // +0x08: opcode/operand1
    char* token2;               // +0x10: operand1/operand2
    char* token3;               // +0x18: operand2
};

struct Tokenizer {
    char**      lines;          // +0x00: Array of raw line strings
    TokenLine** tokens;         // +0x08: Array of parsed token lines
};
