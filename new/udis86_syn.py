from udis86_decode import *
from udis86 import *

ud_reg_tab = (
    "al",   "cl",   "dl",   "bl",
    "ah",   "ch",   "dh",   "bh",
    "spl",  "bpl",  "sil",  "dil",
    "r8b",  "r9b",  "r10b", "r11b",
    "r12b", "r13b", "r14b", "r15b",

    "ax",   "cx",   "dx",   "bx",
    "sp",   "bp",   "si",   "di",
    "r8w",  "r9w",  "r10w", "r11w",
    "r12w", "r13w", "r14w", "r15w",

    "eax",  "ecx",  "edx",  "ebx",
    "esp",  "ebp",  "esi",  "edi",
    "r8d",  "r9d",  "r10d", "r11d",
    "r12d", "r13d", "r14d", "r15d",

    "rax",  "rcx",  "rdx",  "rbx",
    "rsp",  "rbp",  "rsi",  "rdi",
    "r8",   "r9",   "r10",  "r11",
    "r12",  "r13",  "r14",  "r15",

    "es",   "cs",   "ss",   "ds",
    "fs",   "gs",

    "cr0",  "cr1",  "cr2",  "cr3",
    "cr4",  "cr5",  "cr6",  "cr7",
    "cr8",  "cr9",  "cr10", "cr11",
    "cr12", "cr13", "cr14", "cr15",

    "dr0",  "dr1",  "dr2",  "dr3",
    "dr4",  "dr5",  "dr6",  "dr7",
    "dr8",  "dr9",  "dr10", "dr11",
    "dr12", "dr13", "dr14", "dr15",

    "mm0",  "mm1",  "mm2",  "mm3",
    "mm4",  "mm5",  "mm6",  "mm7",

    "st0",  "st1",  "st2",  "st3",
    "st4",  "st5",  "st6",  "st7",

    "xmm0", "xmm1", "xmm2", "xmm3",
    "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11",
    "xmm12", "xmm13", "xmm14", "xmm15",

    "ymm0", "ymm1", "ymm2",   "ymm3",
    "ymm4", "ymm5", "ymm6",   "ymm7",
    "ymm8", "ymm9", "ymm10",  "ymm11",
    "ymm12", "ymm13", "ymm14", "ymm15",

    "rip"
)

def udSynRelTarget(u, opr):
    trunc_mask = 0xffffffffffffffff >> (64 - u.opr_mode)
    if opr.size == 8:
        return (u.pc + opr.lval.sbyte) & trunc_mask
    elif opr.size == 16:
        return (u.pc + opr.lval.sword) & trunc_mask
    elif opr.size == 32:
        return (u.pc + opr.lval.sdword) & trunc_mask
    else:
        raise Exception("invalid relative offset size")
    return 0

def udSynPrintAddr(u, addr):
    if u.sym_resolver != None:
        name, offset = u.sym_resolver(u, addr)
        if name:
            if offset:
                u.asm_buf += "{:s}{:+d}".format(name, offset)
            else:
                u.asm_buf += name
    else:
        u.asm_buf += "0x{:x}".format(addr)


def udSynExpandSign(v, ss, ds):
    if ss >= ds:
        return v

    srcmask = (1 << ss) - 1
    srcsign = (1 << (ss - 1))

    v &= srcmask
    if v & srcsign:
        dstmask = (1 << ds) - 1
        extend = dstmask ^ srcmask
        v |= extend

    return v


def udSynPrintImm(u, op):
    v = 0
    if op._oprcode == OP_sI and op.size != u.opr_mode:
        if op.size == 8:
            v = udSynExpandSign(op.lval.sbyte, 8, 64)
        else:
            if op.size != 32:
                raise Exception("op.size != 32")
            v = udSynExpandSign(op.lval.sdword, 32, 64)

        if u.opr_mode < 64:
            v = v & ((1 << u.opr_mode) - 1)
    else:
        if op.size == 8:
            v = op.lval.ubyte
        elif op.size == 16:
            v = op.lval.uword
        elif op.size == 32:
            v = op.lval.udword
        elif op.size == 64:
            v = op.lval.uqword
        else:
            raise Exception("invalid offset")
            v = 0
    u.asm_buf += "0x{:x}".format(v)

def udSynPrintMemDisp(u, op, sign):
    if op.offset == 0:
        raise Exception("op.offset == 0")

    if op.base == UD_NONE and op.index == UD_NONE:
        if op.scale != UD_NONE or op.offset == 8:
            raise Exception("op.scale != UD_NONE or op.offset == 8")
        v = 0
        if op.offset == 16:
            v = op.lval.uword
        elif op.offset == 32:
            v = op.lval.udword
        elif op.offset == 64:
            v = op.lval.uqword
        else:
            raise Exception("invalid offset")
            v = 0

        u.asm_buf += "0x{:x}".format(v)
    else:
        if op.offset == 64:
            raise Exception("op.offset == 64")
        v = 0
        if op.offset == 8:
            v = op.lval.sbyte
        elif op.offset == 16:
            v = op.lval.sword
        elif op.offset == 32:
            v = op.lval.sdword
        else:
            raise Exception("invalid offset")
            v = 0

        if v < 0:
            u.asm_buf += "-0x{:x}".format(-v)
        elif v > 0:
            if sign:
                u.asm_buf += "+0x{:x}".format(v)
            else:
                u.asm_buf += "0x{:x}".format(v)

def udTranslateUpper(s, upper):
    if upper:
        return s.upper()
    return s

def udTranslateIntelOprCast(u, op):
    if u.br_far:
        u.asm_buf += "far "
    if op.size == 8:
        u.asm_buf += "byte "
    elif op.size == 16:
        u.asm_buf += "word "
    elif op.size == 32:
        u.asm_buf += "dword "
    elif op.size == 64:
        u.asm_buf += "qword "
    elif op.size == 80:
        u.asm_buf += "tword "
    elif op.size == 128:
        u.asm_buf += "oword "
    elif op.size == 256:
        u.asm_buf += "yword "

def udTranslateIntelGenOperand(u, op, syn_cast, upper = False):
    if op.type == UD_OP_REG:
        u.asm_buf += udTranslateUpper(ud_reg_tab[op.base - UD_R_AL], upper)
    elif op.type == UD_OP_MEM:
        if syn_cast:
            udTranslateIntelOprCast(u, op)
        u.asm_buf += "["
        if u.pfx_seg:
            u.asm_buf += udTranslateUpper(ud_reg_tab[u.pfx_seg - UD_R_AL], upper) + ":"
        if op.base:
            u.asm_buf += udTranslateUpper(ud_reg_tab[op.base - UD_R_AL], upper)
        if op.index:
            if op.base != UD_NONE:
                u.asm_buf += "+"
            u.asm_buf += udTranslateUpper(ud_reg_tab[op.index - UD_R_AL], upper)
            if op.scale:
                u.asm_buf += "*{:d}".format(op.scale)
            else:
                u.asm_buf += "*1"

        if op.offset != 0:
            if op.base != UD_NONE or op.index != UD_NONE:
                udSynPrintMemDisp(u, op, 1)
            else:
                udSynPrintMemDisp(u, op, 0)
        u.asm_buf += "]"
    elif op.type == UD_OP_IMM:
        udSynPrintImm(u, op)
    elif op.type == UD_OP_JIMM:
        udSynPrintAddr(u, udSynRelTarget(u, op))
    elif op.type == UD_OP_PTR:
        if op.size == 32:
            u.asm_buf += "word 0x{:x}:0x{:x}".format(op.lval.ptr.seg, op.lval.ptr.off & 0xFFFF)
        elif op.size == 48:
            u.asm_buf += "dword 0x{:x}:0x{:x}".format(op.lval.ptr.seg, op.lval.ptr.off)
    elif op.type == UD_OP_CONST:
        if syn_cast:
            udTranslateIntelOprCast(u, op)
        u.asm_buf += "{:d}".format(op.lval.udword)

def udTranslateIntel(u, upper = False):
    u.asm_buf = ""
    if P_OSO(u.itab_entry.prefix) == 0 and u.pfx_opr:
        if u.dis_mode == 16:
            u.asm_buf += "o32 "
        elif u.dis_mode in (32, 64):
            u.asm_buf += "o16 "

    if P_ASO(u.itab_entry.prefix) == 0 and u.pfx_adr:
        if u.dis_mode == 16:
            u.asm_buf += "a32 "
        elif u.dis_mode == 32:
            u.asm_buf += "a16 "
        elif u.dis_mode == 64:
            u.asm_buf += "a32 "

    if u.pfx_seg and \
       u.operand[0].type != UD_OP_MEM and \
       u.operand[1].type != UD_OP_MEM:
        u.asm_buf += udTranslateUpper( ud_reg_tab[u.pfx_seg - UD_R_AL] + " ", upper )

    if u.pfx_lock:
        u.asm_buf += "lock "
    if u.pfx_rep:
        u.asm_buf += "rep "
    elif u.pfx_repe:
        u.asm_buf += "repe "
    elif u.pfx_repne:
        u.asm_buf += "repne "

    u.asm_buf += udTranslateUpper( udLookupMnemonic(u.mnemonic), upper )

    if u.operand[0].type != UD_NONE:
        cast = 0
        u.asm_buf += " "
        if u.operand[0].type == UD_OP_MEM:
            if u.operand[1].type in (UD_OP_IMM, UD_OP_CONST, UD_NONE) or\
                u.operand[0].size != u.operand[1].size:
                cast = 1
            elif u.operand[1].type == UD_OP_REG and u.operand[1].base == UD_R_CL:
                if u.mnemonic in (UD_Ircl, UD_Irol, UD_Iror, UD_Ircr, UD_Ishl, UD_Ishr, UD_Isar):
                    cast = 1

        udTranslateIntelGenOperand(u, u.operand[0], cast, upper)

    if u.operand[1].type != UD_NONE:
        cast = 0
        u.asm_buf += ", "
        if u.operand[1].type == UD_OP_MEM and\
           u.operand[0].size != u.operand[1].size and\
           not u.operand[0].isSreg():
            cast = 1

        udTranslateIntelGenOperand(u , u.operand[1] , cast , upper)

    if u.operand[2].type != UD_NONE:
        cast = 0
        u.asm_buf += ", "
        if u.operand[2].type == UD_OP_MEM and\
           u.operand[2].size != u.operand[1].size:
            cast = 1

        udTranslateIntelGenOperand(u , u.operand[2] , cast , upper)

    if u.operand[3].type != UD_NONE:
        u.asm_buf += ", "
        udTranslateIntelGenOperand(u , u.operand[3] , 0 , upper)

    return u.asm_buf

