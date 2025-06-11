from udis86_decodeh import *
from udis86_itabh import *
from udis86_itabc import *
from udis86_types import *
from udis86_types import UD_NONE

MAX_PREFIXES =   15

def REX_W(r):
    return ( ( 0xF & ( r ) )  >> 3 )

def REX_R(r):
    return( ( 0x7 & ( r ) )  >> 2 )

def REX_X(r):
    return ( ( 0x3 & ( r ) )  >> 1 )

def REX_B(r):
    return ( ( 0x1 & ( r ) )  >> 0 )

def REX_PFX_MASK(n):
    return ( ( P_REXW(n) << 3 ) |
             ( P_REXR(n) << 2 ) |
             ( P_REXX(n) << 1 ) |
             ( P_REXB(n) << 0 ) )

def SIB_S(b):
    return ( ( b ) >> 6 )

def SIB_I(b):
    return ( ( ( b ) >> 3 ) & 7 )

def SIB_B(b):
    return ( ( b ) & 7 )

def MODRM_REG(b):
    return ( ( ( b ) >> 3 ) & 7 )

def MODRM_NNN(b):
    return ( ( ( b ) >> 3 ) & 7 )

def MODRM_MOD(b):
    return ( ( ( b ) >> 6 ) & 3 )

def MODRM_RM(b):
    return ( ( b ) & 7 )


REGCLASS_GPR = 0
REGCLASS_MMX = 1
REGCLASS_CR = 2
REGCLASS_DB = 3
REGCLASS_SEG = 4
REGCLASS_XMM = 5




UD_R_FAMILY_NONE = 0
UD_R_FAMILY_A = 1
UD_R_FAMILY_C = 2
UD_R_FAMILY_D = 3
UD_R_FAMILY_B = 4
UD_R_FAMILY_SP = 5
UD_R_FAMILY_BP = 6
UD_R_FAMILY_SI = 7
UD_R_FAMILY_DI = 8
UD_R_FAMILY_8 = 9
UD_R_FAMILY_9 = 10
UD_R_FAMILY_10 = 11
UD_R_FAMILY_11 = 12
UD_R_FAMILY_12 = 13
UD_R_FAMILY_13 = 14
UD_R_FAMILY_14 = 15
UD_R_FAMILY_15 = 16

UD_R_NONE_FAMILY = (UD_NONE, UD_NONE, UD_NONE, UD_NONE) #0
UD_R_A_FAMILY = (UD_R_AL, UD_R_AH, UD_R_AX, UD_R_EAX, UD_R_RAX) #1
UD_R_C_FAMILY = (UD_R_CL, UD_R_CH, UD_R_CX, UD_R_ECX, UD_R_RCX) #2
UD_R_D_FAMILY = (UD_R_DL, UD_R_DH, UD_R_DX, UD_R_EDX, UD_R_RDX) #3
UD_R_B_FAMILY = (UD_R_BL, UD_R_BH, UD_R_BX, UD_R_EBX, UD_R_RBX) #4
UD_R_SP_FAMILY = (UD_R_SPL, UD_R_SP, UD_R_ESP, UD_R_RSP) #5
UD_R_BP_FAMILY = (UD_R_BPL, UD_R_BP, UD_R_EBP, UD_R_RBP) #6
UD_R_SI_FAMILY = (UD_R_SIL, UD_R_SI, UD_R_ESI, UD_R_RSI) #7
UD_R_DI_FAMILY = (UD_R_DIL, UD_R_DI, UD_R_EDI, UD_R_RDI) #8
UD_R_8_FAMILY = (UD_R_R8B, UD_R_R8W, UD_R_R8D, UD_R_R8) #9
UD_R_9_FAMILY = (UD_R_R9B, UD_R_R9W, UD_R_R9D, UD_R_R9) #10
UD_R_10_FAMILY = (UD_R_R10B, UD_R_R10W, UD_R_R10D, UD_R_R10) #11
UD_R_11_FAMILY = (UD_R_R11B, UD_R_R11W, UD_R_R11D, UD_R_R11) #12
UD_R_12_FAMILY = (UD_R_R12B, UD_R_R12W, UD_R_R12D, UD_R_R12) #13
UD_R_13_FAMILY = (UD_R_R13B, UD_R_R13W, UD_R_R13D, UD_R_R13) #14
UD_R_14_FAMILY = (UD_R_R14B, UD_R_R14W, UD_R_R14D, UD_R_R14) #15
UD_R_15_FAMILY = (UD_R_R15B, UD_R_R15W, UD_R_R15D, UD_R_R15) #16



UD_R_FAMILIES = ( UD_R_NONE_FAMILY, UD_R_A_FAMILY, UD_R_C_FAMILY, UD_R_D_FAMILY, UD_R_B_FAMILY,
                 UD_R_SP_FAMILY, UD_R_BP_FAMILY, UD_R_SI_FAMILY, UD_R_DI_FAMILY,
                 UD_R_8_FAMILY, UD_R_9_FAMILY, UD_R_10_FAMILY, UD_R_11_FAMILY,
                 UD_R_12_FAMILY, UD_R_13_FAMILY, UD_R_14_FAMILY, UD_R_15_FAMILY )

UD_R_FAMILY_LOOKUP = dict()

for i, f in enumerate(UD_R_FAMILIES):
    for r in f:
        UD_R_FAMILY_LOOKUP[r] = i



def udBaseFamily(base):
    return UD_R_FAMILY_LOOKUP.get(base, UD_R_FAMILY_NONE)

def udResizeBase(base, newSize):
    f = UD_R_FAMILY_LOOKUP.get(base, UD_R_FAMILY_NONE)
    sz = 0
    if f in (UD_R_FAMILY_A, UD_R_FAMILY_C, UD_R_FAMILY_D, UD_R_FAMILY_B):
        sz = {8: 0, 16: 2, 32: 3, 64: 4}[newSize]
    else:
        sz = {8: 0, 16: 1, 32: 2, 64: 3}[newSize]
    return UD_R_FAMILIES[f][sz]

def udFamilyReg(family, size):
    if family in (UD_R_FAMILY_A, UD_R_FAMILY_C, UD_R_FAMILY_D, UD_R_FAMILY_B):
        size = {8: 0, 16: 2, 32: 3, 64: 4}[size]
    else:
        size = {8: 0, 16: 1, 32: 2, 64: 3}[size]
    return UD_R_FAMILIES[family][size]

class ud_operand:
    type = UD_NONE
    size = 0
    base = 0
    index = 0
    scale = 0
    offset = 0
    lval = 0

    _oprcode = 0

    def __init__(self):
        self.lval = ud_lval()

    def Copy(self):
        tmp = ud_operand()
        tmp.type = self.type
        tmp.size = self.size
        tmp.base = self.base
        tmp.index = self.index
        tmp.scale = self.scale
        tmp.offset = self.offset
        tmp.lval.lval = self.lval.lval
        tmp._oprcode = self._oprcode
        return tmp

    def isSreg(self):
        return self.type == UD_OP_REG and self.base >= UD_R_ES and self.base <= UD_R_GS

    def isSame(self, opr):
        return self.type == opr.type and self.size == opr.size and \
               self.base == opr.base and self.index == opr.index and \
               self.scale == opr.scale and self.offset == opr.offset and\
               self.lval.lval == opr.lval.lval

    #is same base index scale offset
    def isSameBISO(self, opr):
        return self.base == opr.base and self.index == opr.index and self.scale == opr.scale and self.lval.udword == opr.lval.udword

    def getVal(self, signed = False):
        return self.lval.GetVal(self.size, signed)

    def isBaseFamily(self, reg):
        if type(reg) in (list, tuple):
            sfamily = UD_R_FAMILY_LOOKUP.get(self.base, UD_R_FAMILY_NONE)
            for r in reg:
                if sfamily == UD_R_FAMILY_LOOKUP.get(r, UD_R_FAMILY_NONE):
                    return True
            return False
        else:
            return UD_R_FAMILY_LOOKUP.get(self.base, UD_R_FAMILY_NONE) == UD_R_FAMILY_LOOKUP.get(reg, UD_R_FAMILY_NONE)

    def getBaseHigh(self):
        famid = UD_R_FAMILY_LOOKUP.get(self.base, UD_R_FAMILY_NONE)
        if famid in (UD_R_FAMILY_A, UD_R_FAMILY_C, UD_R_FAMILY_D, UD_R_FAMILY_B):
            return (UD_R_AH, UD_R_CH, UD_R_DH, UD_R_BH)[famid]
        return UD_NONE


    def BIS(self):
        return (self.base, self.index, self.scale)

    def BISO(self):
        return (self.base, self.index, self.scale, self.lval.lval)

    def TSZ(self):
        return (self.type, self.size)

    def Family(self):
        return UD_R_FAMILY_LOOKUP.get(self.base, UD_R_FAMILY_NONE)

    def CopyValues(self, op):
        self.type = op.type
        self.size = op.size
        self.base = op.base
        self.index = op.index
        self.scale = op.scale
        self.offset = op.offset
        self.lval.lval = op.lval.lval


class ud:
    dis_mode = 0
    pc = 0
    vendor = 0
    mnemonic = UD_Inone
    operand = None

    inp_end = True
    inp_buf = None
    inp_buf_index = 0
    inp_peek = 0

    inp_ctr = 0
    inp_curr = 0
    inp_sess = None

    inp_hook = None

    error = 0
    errMsg = ""

    pfx_rex = 0
    pfx_seg = 0
    pfx_opr = 0
    pfx_adr = 0
    pfx_lock = 0
    pfx_str = 0
    pfx_rep = 0
    pfx_repe = 0
    pfx_repne = 0

    opr_mode = 0
    adr_mode = 0
    br_far = 0
    br_near = 0
    have_modrm = False
    modrm = 0
    modrm_offset = 0
    vex_op = 0
    vex_b1 = 0
    vex_b2 = 0
    primary_opcode = 0

    itab_entry = None
    le = None

    insn_offset = 0
    asm_buf = ""
    sym_resolver = None


    def __init__(self, dis_mode = 32):
        self.operand = [ud_operand(), ud_operand(), ud_operand(), ud_operand()]
        self.inp_sess = [0] * 64
        self.dis_mode = dis_mode

    def Copy(self):
        tmp = ud()
        tmp.dis_mode = self.dis_mode
        tmp.pc = self.pc
        tmp.vendor = self.vendor
        tmp.mnemonic = self.mnemonic
        tmp.operand[0] = self.operand[0].Copy()
        tmp.operand[1] = self.operand[1].Copy()
        tmp.operand[2] = self.operand[2].Copy()
        tmp.operand[3] = self.operand[3].Copy()
        tmp.inp_end = self.inp_end
        tmp.inp_buf = self.inp_buf
        tmp.inp_buf_index = self.inp_buf_index
        tmp.inp_peek = self.inp_peek

        tmp.inp_ctr = self.inp_ctr
        tmp.inp_curr = self.inp_curr
        tmp.inp_sess = self.inp_sess

        tmp.inp_hook = self.inp_hook

        tmp.error = self.error
        tmp.errMsg = self.errMsg

        tmp.pfx_rex = self.pfx_rex
        tmp.pfx_seg = self.pfx_seg
        tmp.pfx_opr = self.pfx_opr
        tmp.pfx_adr = self.pfx_adr
        tmp.pfx_lock = self.pfx_lock
        tmp.pfx_str = self.pfx_str
        tmp.pfx_rep = self.pfx_rep
        tmp.pfx_repe = self.pfx_repe
        tmp.pfx_repne = self.pfx_repne

        tmp.opr_mode = self.opr_mode
        tmp.adr_mode = self.adr_mode
        tmp.br_far = self.br_far
        tmp.br_near = self.br_near
        tmp.have_modrm = self.have_modrm
        tmp.modrm = self.modrm
        tmp.modrm_offset = self.modrm_offset
        tmp.vex_op = self.vex_op
        tmp.vex_b1 = self.vex_b1
        tmp.vex_b2 = self.vex_b2
        tmp.primary_opcode = self.primary_opcode

        tmp.itab_entry = self.itab_entry
        tmp.le = self.le

        tmp.insn_offset = self.insn_offset
        tmp.asm_buf = self.asm_buf
        tmp.sym_resolver = self.sym_resolver
        return tmp

    def CopyPrefixes(self, u):
        self.pfx_rex = u.pfx_rex
        self.pfx_seg = u.pfx_seg
        self.pfx_opr = u.pfx_opr
        self.pfx_adr = u.pfx_adr
        self.pfx_lock = u.pfx_lock
        self.pfx_str = u.pfx_str
        self.pfx_rep = u.pfx_rep
        self.pfx_repe = u.pfx_repe
        self.pfx_repne = u.pfx_repne

    def UDERR(self, m):
        if self.error == 0:
            self.errMsg = m
            self.error = 1
            print(m)
        return 1

    def inpStart(self):
        self.inp_ctr = 0

    def inpPeek(self):
        if self.inp_end == False:
            if self.inp_buf != None:
                if self.inp_buf_index < len(self.inp_buf):
                    return self.inp_buf[self.inp_buf_index]
            elif self.inp_peek != UD_EOI:
                return self.inp_peek
            else:
                c = self.inp_hook(self)
                if c != UD_EOI:
                    self.inp_peek = c
                    return c
        self.inp_end = True
        self.UDERR("byte expected, eoi received")
        return 0

    def inpNext(self):
        if self.inp_end == False:
            if self.inp_buf != None:
                if self.inp_buf_index < len(self.inp_buf):
                    self.inp_ctr += 1
                    self.inp_curr = self.inp_buf[self.inp_buf_index]
                    self.inp_buf_index += 1
                    return self.inp_curr
            else:
                c = self.inp_peek
                if c == UD_EOI:
                    c = self.inp_hook(self)
                if c != UD_EOI:
                    self.inp_peek = UD_EOI
                    self.inp_curr = c
                    self.inp_sess[self.inp_ctr] = c
                    self.inp_ctr += 1
                    return c
        self.inp_end = True
        self.UDERR("byte expected, eoi received")
        return 0

    def inpCurr(self):
        return self.inp_curr

    def inpUint8(self):
        return self.inpNext()

    def inpUint16(self):
        a = self.inpNext()
        b = self.inpNext()
        return a | (b << 8)

    def inpUint32(self):
        v = 0
        for i in range(4):
            v |= self.inpNext() << (i * 8)
        return v

    def inpUint64(self):
        v = 0
        for i in range(8):
            v |= self.inpNext() << (i * 8)
        return v

    @staticmethod
    def effOprMode(dis_mode, rex_w, pfx_opr):
        if dis_mode == 64:
            if rex_w:
                return 64
            if pfx_opr:
                return 16
            return 32
        elif dis_mode == 32:
            if pfx_opr:
                return 16
            return 32
        else:
            if dis_mode != 16:
                print("effOprMode dis_mode != 16")
                raise Exception
            if pfx_opr:
                return 32
            return 16

    @staticmethod
    def effAdrMode(dis_mode , pfx_adr):
        if dis_mode == 64:
            if pfx_adr:
                return 32
            return 64
        elif dis_mode == 32:
            if pfx_adr:
                return 16
            return 32
        else:
            if dis_mode != 16:
                print("eff_adr_mode dis_mode != 16")
                raise Exception
            if pfx_adr:
                return 32
            return 16

    def decodePrefixes(self):
        done = 0
        curr = 0
        last = 0

        if self.error != 0:
            return self.error

        if self.inp_ctr >= MAX_INSN_LENGTH:
            return self.UDERR("max instruction length")

        while done == 0:
            last = curr
            curr = self.inpNext()

            if self.error != 0:
                return self.error

            if self.inp_ctr >= MAX_INSN_LENGTH:
                return self.UDERR("max instruction length")

            if curr == 0x2e:
                self.pfx_seg = UD_R_CS
            elif curr == 0x36:
                self.pfx_seg = UD_R_SS
            elif curr == 0x3e:
                self.pfx_seg = UD_R_DS
            elif curr == 0x26:
                self.pfx_seg = UD_R_ES
            elif curr == 0x64:
                self.pfx_seg = UD_R_FS
            elif curr == 0x65:
                self.pfx_seg = UD_R_GS
            elif curr == 0x67:
                self.pfx_adr = 0x67
            elif curr == 0xf0:
                self.pfx_lock = 0xf0
            elif curr == 0x66:
                self.pfx_opr = 0x66
            elif curr == 0xf2:
                self.pfx_str = 0xf2
            elif curr == 0xf3:
                self.pfx_str = 0xf3
            else:
                done = 1
                if self.dis_mode == 64 and (curr & 0xf0) == 0x40:
                    done = 0

        if self.dis_mode == 64 and (last & 0xf0) == 0x40:
            self.pfx_rex = last
        return 0

    def vex_l(self):
        if self.vex_op == 0:
            print("u->vex_op != 0")
            raise Exception
        if self.vex_op == 0xc4:
            return (self.vex_b2 >> 2) & 1
        else:
            return (self.vex_b1 >> 2) & 1

    def vex_w(self):
        if self.vex_op == 0:
            print("u->vex_op != 0")
            raise Exception
        if self.vex_op == 0xc4:
            return (self.vex_b2 >> 7) & 1
        else:
            return 0

    def modRm(self):
        if (not self.have_modrm):
            self.modrm = self.inpNext()
            self.modrm_offset = self.inp_ctr - 1
            self.have_modrm = True
        return self.modrm

    def resolveOperandSize(self, osize):
        if osize == SZ_V:
            return self.opr_mode
        elif osize == SZ_Z:
            if self.opr_mode == 16:
                return 16
            return 32
        elif osize == SZ_Y:
            if self.opr_mode == 16:
                return 32
            return self.opr_mode
        elif osize == SZ_RDQ:
            if self.dis_mode == 64:
                return 64
            return 32
        elif osize == SZ_X:
            if self.vex_op == 0:
                print("u->vex_op != 0")
                raise Exception
            if P_VEXL(self.itab_entry.prefix) and self.vex_l():
                return SZ_QQ
            return SZ_DQ
        return osize

    def resolveMnemonic(self):
        if self.mnemonic == UD_I3dnow:
            self.mnemonic = ud_itab[ self.le.table[ self.inp_curr() ] ].mnemonic

        if self.mnemonic == UD_Iswapgs and self.dis_mode != 64:
            self.UDERR("swapgs invalid in 64bits mode")
            return -1

        if self.mnemonic == UD_Ixchg:
            if (self.operand[0].type == UD_OP_REG and self.operand[0].base == UD_R_AX and\
                self.operand[1].type == UD_OP_REG and self.operand[1].base == UD_R_AX) or \
               (self.operand[0].type == UD_OP_REG and self.operand[0].base == UD_R_EAX and\
                self.operand[1].type == UD_OP_REG and self.operand[1].base == UD_R_EAX):
                self.operand[0].type = UD_NONE
                self.operand[1].type = UD_NONE
                self.mnemonic = UD_Inop

        if self.mnemonic == UD_Inop and self.pfx_repe:
            self.pfx_repe = 0
            self.mnemonic = UD_Ipause

        return 0

    def decodeA(self, op):
        if self.opr_mode == 16:
            op.type = UD_OP_PTR
            op.size = 32
            op.lval.ptr.off = self.inpUint16()
            op.lval.ptr.seg = self.inpUint16()
        else:
            op.type = UD_OP_PTR
            op.size = 48
            op.lval.ptr.off = self.inpUint32()
            op.lval.ptr.seg = self.inpUint16()

    def decodeGPR(self, s, rm):
        if s == 64:
            return UD_R_RAX + rm
        elif s == 32:
            return UD_R_EAX + rm
        elif s == 16:
            return UD_R_AX + rm
        elif s == 8:
            if self.dis_mode == 64 and self.pfx_rex and rm >= 4:
                return UD_R_SPL + (rm - 4)
            return UD_R_AL + rm
        elif s == 0:
            if self.error == 0:
                print(self.error)
                raise Exception
            return UD_NONE
        else:
            print("Invalid operand size")
            raise Exception
        return UD_NONE

    def decodeReg(self, opr, tp, num, size):
        size = self.resolveOperandSize(size)
        reg = 0
        if tp == REGCLASS_GPR:
            reg = self.decodeGPR(size, num)
        elif tp == REGCLASS_MMX:
            reg = UD_R_MM0 + (num & 7)
        elif tp == REGCLASS_XMM:
            if size == SZ_QQ:
                reg = UD_R_YMM0 + num
            else:
                reg = UD_R_XMM0 + num
        elif tp == REGCLASS_CR:
            reg = UD_R_CR0 + num
        elif tp == REGCLASS_DB:
            reg = UD_R_DR0 + num
        elif tp == REGCLASS_SEG:
            if (num & 7) > 5:
                self.UDERR("invalid segment register value")
                return
            else:
                reg = UD_R_ES + (num & 7)
        else:
            raise Exception("invalid register type")
        opr.type = UD_OP_REG
        opr.base = reg
        opr.size = size

    def decodeImm(self, size, op):
        op.size = self.resolveOperandSize(size)
        op.type = UD_OP_IMM

        if op.size == 8:
            op.lval.ubyte = self.inpUint8()
        elif op.size == 16:
            op.lval.uword = self.inpUint16()
        elif op.size == 32:
            op.lval.udword = self.inpUint32()
        elif op.size == 64:
            op.lval.uqword = self.inpUint64()

    def decodeMemDisp(self, size, op):
        if size == 8:
            op.offset = 8
            op.lval.ubyte = self.inpUint8()
        elif size == 16:
            op.offset = 16
            op.lval.uword = self.inpUint16()
        elif size == 32:
            op.offset = 32
            op.lval.udword = self.inpUint32()
        elif size == 64:
            op.offset = 64
            op.lval.uqword = self.inpUint64()

    def decodeModRmReg(self, operand, tp, size):
        reg = (REX_R(self._rex) << 3) | MODRM_REG( self.modRm() )
        self.decodeReg(operand, tp, reg, size)

    def decodeModRmRm(self, op, tp, size):
        offset = 0
        mod = MODRM_MOD( self.modRm() )
        rm = (REX_B(self._rex) << 3) | MODRM_RM( self.modRm() )

        if mod == 3:
            self.decodeReg(op, tp, rm, size)
            return

        op.type = UD_OP_MEM
        op.size = self.resolveOperandSize(size)

        if self.adr_mode == 64:
            op.base = UD_R_RAX + rm
            if mod == 1:
                offset = 8
            elif mod == 2:
                offset = 32
            elif mod == 0 and (rm & 7) == 5:
                op.base = UD_R_RIP
                offset = 32
            else:
                offset = 0

            if (rm & 7) == 4:
                self.inpNext()

                op.base = UD_R_RAX + (SIB_B(self.inpCurr()) | (REX_B(self._rex) << 3))
                op.index = UD_R_RAX + (SIB_I(self.inpCurr()) | (REX_X(self._rex) << 3))

                if op.index == UD_R_RSP:
                    op.index = UD_NONE
                    op.scale = UD_NONE
                else:
                    op.scale = (1 << SIB_S( self.inpCurr() )) & ~1

                if op.base == UD_R_RBP or op.base == UD_R_R13:
                    if mod == 0:
                        op.base = UD_NONE
                    if mod == 1:
                        offset = 8
                    else:
                        offset = 32
            else:
                op.scale = UD_NONE
                op.index = UD_NONE

        elif self.adr_mode == 32:
            op.base = UD_R_EAX + rm
            if mod == 1:
                offset = 8
            elif mod == 2:
                offset = 32
            elif mod == 0 and rm == 5:
                op.base = UD_R_RIP
                offset = 32
            else:
                offset = 0

            if (rm & 7) == 4:
                self.inpNext()

                op.scale = (1 << SIB_S(self.inpCurr())) & ~1
                op.index = UD_R_EAX + (SIB_I(self.inpCurr()) | (REX_X(self._rex) << 3))
                op.base = UD_R_EAX + (SIB_B(self.inpCurr()) | (REX_B(self._rex) << 3))

                if op.index == UD_R_ESP:
                    op.index = UD_NONE
                    op.scale = UD_NONE

                if op.base == UD_R_EBP:
                    if mod == 0:
                        op.base = UD_NONE
                    if mod == 1:
                        offset = 8
                    else:
                        offset = 32
            else:
                op.scale = UD_NONE
                op.index = UD_NONE
        else:
            bases = (UD_R_BX, UD_R_BX, UD_R_BP, UD_R_BP, UD_R_SI, UD_R_DI, UD_R_BP, UD_R_BX)
            indices = (UD_R_SI, UD_R_DI, UD_R_SI, UD_R_DI, UD_NONE, UD_NONE, UD_NONE, UD_NONE)

            op.base = bases[ rm & 7 ]
            op.index = indices[ rm & 7 ]
            op.scale = UD_NONE

            if mod == 0 and rm == 6:
                offset = 16
                op.base = UD_NONE
            elif mod == 1:
                offset = 8
            elif mod == 2:
                offset = 16

        if offset:
            self.decodeMemDisp(offset, op)
        else:
            op.offset = 0

    def decodeMoffset(self, size, opr):
        opr.type = UD_OP_MEM
        opr.base = UD_NONE
        opr.index = UD_NONE
        opr.scale = UD_NONE
        opr.size = self.resolveOperandSize(size)
        self.decodeMemDisp(self.adr_mode, opr)

    def decodeVexVVVV(self, opr, size):
        if self.vex_op == 0:
            raise Exception("vex_op != 0")
        vvvv = 0
        if self.vex_op == 0xc4:
            vvvv = (self.vex_b2 >> 3) & 0xf
        else:
            vvvv = (self.vex_b1 >> 3) & 0xf

        self.decodeReg(opr, REGCLASS_XMM, (0xf & ~vvvv), size)

    def decodeVexImmReg(self, opr, size):
        imm = self.inpNext()
        mask = 7
        if self.dis_mode == 64:
            mask = 0xf

        if self.error != 0:
            return self.error

        if self.vex_op == 0:
            raise Exception("vex_op != 0")

        self.decodeReg(opr, REGCLASS_XMM, mask & (imm >> 4), size)
        return 0

    def decodeOperand(self, operand, tp, size):
        operand.type = UD_NONE
        operand._oprcode = tp

        if tp == OP_A:
            self.decodeA(operand)
        elif tp == OP_MR:
            if MODRM_MOD( self.modRm() ) == 3:
                self.decodeModRmRm(operand, REGCLASS_GPR, Mx_reg_size(size))
            else:
                self.decodeModRmRm(operand, REGCLASS_GPR, Mx_mem_size(size))
        elif tp == OP_F:
            self.br_far = 1
            if MODRM_MOD( self.modRm() ) == 3:
                self.UDERR("expected modrm.mod != 3")
            self.decodeModRmRm(operand, REGCLASS_GPR, size)
        elif tp == OP_M:
            if MODRM_MOD( self.modRm() ) == 3:
                self.UDERR("expected modrm.mod != 3")
            self.decodeModRmRm(operand, REGCLASS_GPR, size)
        elif tp == OP_E:
            self.decodeModRmRm(operand, REGCLASS_GPR, size)
        elif tp == OP_G:
            self.decodeModRmReg(operand, REGCLASS_GPR, size)
        elif tp in (OP_sI, OP_I):
            self.decodeImm(size, operand)
        elif tp == OP_I1:
            operand.type = UD_OP_CONST
            operand.lval.udword = 1
        elif tp == OP_N:
            if MODRM_MOD( self.modRm()) != 3:
                self.UDERR("expected modrm.mod == 3")
            self.decodeModRmRm(operand, REGCLASS_MMX, size)
        elif tp == OP_Q:
            self.decodeModRmRm(operand, REGCLASS_MMX, size)
        elif tp == OP_P:
            self.decodeModRmReg(operand, REGCLASS_MMX, size)
        elif tp == OP_U:
            if MODRM_MOD( self.modRm()) != 3:
                self.UDERR("expected modrm.mod == 3")
            self.decodeModRmRm(operand, REGCLASS_XMM, size)
        elif tp == OP_W:
            self.decodeModRmRm(operand, REGCLASS_XMM, size)
        elif tp == OP_V:
            self.decodeModRmReg(operand, REGCLASS_XMM, size)
        elif tp == OP_H:
            self.decodeVexVVVV(operand, size)
        elif tp == OP_MU:
            if MODRM_MOD( self.modRm() ) == 3:
                self.decodeModRmRm(operand, REGCLASS_XMM, Mx_reg_size(size))
            else:
                self.decodeModRmRm(operand , REGCLASS_XMM , Mx_mem_size(size))
        elif tp == OP_S:
            self.decodeModRmReg(operand, REGCLASS_SEG, size)
        elif tp == OP_O:
            self.decodeMoffset(size, operand)
        elif tp in (OP_R0, OP_R1, OP_R2, OP_R3, OP_R4, OP_R5, OP_R6, OP_R7):
            self.decodeReg(operand, REGCLASS_GPR, (REX_B(self._rex) << 3) | (tp - OP_R0), size)
        elif tp in (OP_AL , OP_AX , OP_eAX , OP_rAX):
            self.decodeReg(operand, REGCLASS_GPR, 0, size)
        elif tp in (OP_CL , OP_CX , OP_eCX):
            self.decodeReg(operand, REGCLASS_GPR, 1, size)
        elif tp in (OP_DL , OP_DX , OP_eDX):
            self.decodeReg(operand, REGCLASS_GPR, 2, size)
        elif tp in (OP_ES, OP_CS, OP_DS, OP_SS, OP_FS, OP_GS):
            if self.dis_mode == 64:
                if tp not in (OP_FS, OP_GS):
                    self.UDERR("invalid segment register in 64bits")

            operand.type = UD_OP_REG
            operand.base = (tp - OP_ES) + UD_R_ES
            operand.size = 16
        elif tp == OP_J:
            self.decodeImm(size, operand)
            operand.type = UD_OP_JIMM
        elif tp == OP_R:
            if MODRM_MOD(self.modRm()) != 3:
                self.UDERR("expected modrm.mod == 3")
            self.decodeModRmRm(operand, REGCLASS_GPR, size)
        elif tp == OP_C:
            self.decodeModRmReg(operand, REGCLASS_CR, size)
        elif tp == OP_D:
            self.decodeModRmReg(operand, REGCLASS_DB, size)
        elif tp == OP_I3:
            operand.type = UD_OP_CONST
            operand.lval.sbyte = 3
        elif tp in (OP_ST0, OP_ST1, OP_ST2, OP_ST3, OP_ST4, OP_ST5, OP_ST6, OP_ST7):
            operand.type = UD_OP_REG
            operand.base = (tp - OP_ST0) + UD_R_ST0
            operand.size = 80
        elif tp == OP_L:
            self.decodeVexImmReg(operand, size)
        else:
            operand.type = UD_NONE

        return operand.type

    def decodeOperands(self):
        self.decodeOperand(self.operand[0], self.itab_entry.operand1.type, self.itab_entry.operand1.size)

        if self.operand[0].type != UD_NONE:
            self.decodeOperand(self.operand[1] , self.itab_entry.operand2.type , self.itab_entry.operand2.size)

        if self.operand[1].type != UD_NONE:
            self.decodeOperand(self.operand[2] , self.itab_entry.operand3.type , self.itab_entry.operand3.size)

        if self.operand[2].type != UD_NONE:
            self.decodeOperand(self.operand[3] , self.itab_entry.operand4.type , self.itab_entry.operand4.size)

        return 0

    def clearInsn(self):
        self.error = 0
        self.pfx_seg = 0
        self.pfx_opr = 0
        self.pfx_adr = 0
        self.pfx_lock = 0
        self.pfx_repne = 0
        self.pfx_rep = 0
        self.pfx_repe = 0
        self.pfx_rex = 0
        self.pfx_str = 0
        self.mnemonic = UD_Inone
        self.itab_entry = None
        self.have_modrm = 0
        self.br_far = 0
        self.vex_op = 0
        self._rex = 0
        self.operand[0] = ud_operand()
        self.operand[1] = ud_operand()
        self.operand[2] = ud_operand()
        self.operand[3] = ud_operand()

    def resolvePfxStr(self):
        if self.pfx_str == 0xf3:
            if P_STR(self.itab_entry.prefix):
                self.pfx_rep = 0xf3
            else:
                self.pfx_repe = 0xf3
        elif self.pfx_str == 0xf2:
            self.pfx_repne = 0xf3
        return 0

    def resolveMode(self):
        if self.error != 0:
            return -1

        if self.dis_mode == 64:
            if P_INV64( self.itab_entry.prefix ):
                self.UDERR("instruction invalid in 64bits")
                return -1

            if self.vex_op == 0xc4:
                self._rex = ((~(self.vex_b1 >> 5) & 0x7) | # rex.0rxb
                              ((self.vex_b2 >> 4) & 0x8))  # rex.w000
            elif self.vex_op == 0xc5:
                self._rex = (~(self.vex_b1 >> 5)) & 4
            else:
                if self.vex_op != 0:
                    print("vex_op == 0")
                    raise Exception
                self._rex = self.pfx_rex

            self._rex &= REX_PFX_MASK( self.itab_entry.prefix )

            default64 = P_DEF64( self.itab_entry.prefix )

            if REX_W(self._rex):
                self.opr_mode = 64
            elif self.pfx_opr:
                self.opr_mode = 16
            elif default64:
                self.opr_mode = 64
            else:
                self.opr_mode = 32

            if self.pfx_adr:
                self.adr_mode = 32
            else:
                self.adr_mode = 64
        elif self.dis_mode == 32:
            if self.pfx_opr:
                self.opr_mode = 16
            else:
                self.opr_mode = 32

            if self.pfx_adr:
                self.adr_mode = 16
            else:
                self.adr_mode = 32
        elif self.dis_mode == 16:
            if self.pfx_opr:
                self.opr_mode = 32
            else:
                self.opr_mode = 16

            if self.pfx_adr:
                self.adr_mode = 32
            else:
                self.adr_mode = 16
        return 0

    def decodeInsn(self, ptr):
        if (ptr & 0x8000) != 0:
            print("(ptr & 0x8000) == 0")
            raise Exception
        self.itab_entry = ud_itab[ ptr ]
        self.mnemonic = self.itab_entry.mnemonic
        if self.resolvePfxStr() != 0 or\
            self.resolveMode() != 0 or\
            self.decodeOperands() != 0 or\
            self.resolveMnemonic() != 0:
            return -1
        return 0

    def decode3dnow(self):
        if self.le.type != UD_TAB__OPC_3DNOW:
            raise Exception("le.type != UD_TAB__OPC_3DNOW")
        if self.le.table[0xc] == 0:
            raise Exception("le.table[0xc] == 0")

        self.decodeInsn(self.le.table[0xc])
        self.inpNext()
        if self.error != 0:
            return -1

        ptr = self.le.table[ self.inpCurr() ]

        if (ptr & 0x8000) != 0:
            raise Exception("(ptr & 0x8000) != 0")

        self.mnemonic = ud_itab[ptr].mnemonic
        return 0

    def decodeSSEpfx(self):
        pfx = self.pfx_str
        if pfx == 0:
            pfx = self.pfx_opr

        idx = ((pfx & 0xf) + 1) // 2
        if self.le.table[idx] == 0:
            idx = 0

        if idx and self.le.table[idx] != 0:
            self.pfx_str = 0
            if pfx == 0x66:
                self.pfx_opr = 0

        return self.decodeExt(self.le.table[idx])

    def decodeVex(self):
        if self.dis_mode != 64 and MODRM_MOD( self.inpPeek() ) != 0x3:
            return self.decodeExt(self.le.table[0])

        self.vex_op = self.inpCurr()
        self.vex_b1 = self.inpNext()

        index = 0
        if self.vex_op == 0xc4:
            self.vex_b2 = self.inpNext()

            if self.error != 0:
                return self.error

            m = self.vex_b1 & 0x1f
            if m == 0 or m > 3:
                return self.UDERR("reserved vex.m-mmmm value")

            pp = self.vex_b2 & 3
            index = (pp < 2) | m
        else:
            if self.vex_op != 0xc5:
                raise Exception("vex_op != 0xc5")
            index = 1 | ((self.vex_b1 & 3) << 2)

        return self.decodeExt(self.le.table[index])

    def decodeExt(self, ptr):
        idx = 0
        if (ptr & 0x8000) == 0:
            return self.decodeInsn(ptr)

        self.le = ud_lookup_table_list[ (~0x8000 & ptr) ]

        letype = self.le.type
        if letype == UD_TAB__OPC_3DNOW:
            return self.decode3dnow()

        if letype == UD_TAB__OPC_MOD:
            idx = ( MODRM_MOD( self.modRm() ) + 1 ) // 4
        elif letype == UD_TAB__OPC_MODE:
            idx = 0
            if self.dis_mode == 64:
                idx = 1
        elif letype == UD_TAB__OPC_OSIZE:
            idx = self.effOprMode(self.dis_mode, REX_W(self.pfx_rex), self.pfx_opr) // 32
        elif letype == UD_TAB__OPC_ASIZE:
            idx = self.effAdrMode(self.dis_mode, self.pfx_adr) // 32
        elif letype == UD_TAB__OPC_X87:
            idx = self.modRm() - 0xc0
        elif letype == UD_TAB__OPC_VENDOR:
            if self.vendor == UD_VENDOR_ANY:
                idx = 0
                if self.le.table[idx] == 0:
                    idx = 1
            elif self.vendor == UD_VENDOR_AMD:
                idx = 0
            else:
                idx = 1
        elif letype == UD_TAB__OPC_RM:
            idx = MODRM_RM(self.modRm())
        elif letype == UD_TAB__OPC_REG:
            idx = MODRM_REG(self.modRm())
        elif letype == UD_TAB__OPC_SSE:
            return self.decodeSSEpfx()
        elif letype == UD_TAB__OPC_VEX:
            return self.decodeVex()
        elif letype == UD_TAB__OPC_VEX_W:
            idx = self.vex_w()
        elif letype == UD_TAB__OPC_VEX_L:
            idx = self.vex_l()
        elif letype == UD_TAB__OPC_TABLE:
            self.inpNext()
            return self.decodeOpcode()
        else:
            print("not reached")
            raise Exception

        return self.decodeExt(self.le.table[ idx ])

    def decodeOpcode(self):
        if self.le.type != UD_TAB__OPC_TABLE:
            print("self.le.type == UD_TAB__OPC_TABLE")
            raise Exception
        if self.error != 0:
            return self.error
        ptr = self.le.table[ self.inpCurr() ]
        return self.decodeExt(ptr)

    def decode(self):
        self.inpStart()
        self.clearInsn()

        self.le = ud_lookup_table_list[0]
        self.error = 0

        if self.decodePrefixes() == -1 or self.decodeOpcode() == -1:
            self.error = 1

        if self.error != 0:
            self.clearInsn()
            self.itab_entry = ud_itab[0]
            self.mnemonic = self.itab_entry.mnemonic

        if P_SEG( self.itab_entry.prefix) == 0 and\
            self.operand[0].type != UD_OP_MEM and\
            self.operand[0].type != UD_OP_MEM:
            self.pfx_seg = 0

        self.insn_offset = self.pc
        self.pc += self.inp_ctr

        return self.inp_ctr

    def setBuf(self, buf):
        self.inp_buf_index = 0
        self.inp_buf = buf
        self.inp_end = False


