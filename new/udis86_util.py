from udis86_decode import *
from udis86_itabh import *
from udis86_types import *
from xrkutil import *

EFLG_CF = (1<<0)
EFLG_PF = (1<<2)
EFLG_AF = (1<<4)
EFLG_ZF = (1<<6)
EFLG_SF = (1<<7)
EFLG_TF = (1<<8)
EFLG_IF = (1<<9)
EFLG_DF = (1<<10)
EFLG_OF = (1<<11)
EFLG_IOPL = (3<<12)
EFLG_NT = (1<<14)
EFLG_RF = (1<<16)
EFLG_VM = (1<<17)
EFLG_AC = (1<<18)
EFLG_VIF = (1<<19)
EFLG_VIP = (1<<20)
EFLG_ID = (1<<21)

class EFlags:
	CF = False #0
	PF = False #2
	AF = False #4
	ZF = False #6
	SF = False #7
	TF = False #8
	IF = False #9
	DF = False #10
	OF = False #11
	IOPL = 0 #12-13
	NT = False #14
	RF = False #16
	VM = False #17
	AC = False #18
	VIF = False #19
	VIP = False #20
	ID = False #21

def CalcEFlags(opid, sz, val1, val2, flags):
    if sz == 8:
        v1 = UB(val1)
        v2 = UB(val2)
        r = 0
        flg = 0
        if opid == UD_Inot:
            pass
        elif opid == UD_Iadd:
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_CF | EFLG_PF
            r = v1 + v2
        elif opid == UD_Iand:
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0
            r = v1 & v2
        elif opid == UD_Idec:
            r = v1 - 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Iinc:
            r = v1 + 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Ineg:
            r = v1 + 1
            if v1 == 0:
                flags.CF = 0
            else:
                flags.CF = 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Ior:
            r = v1 | v2
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0
        elif opid == UD_Ishl:
            cnt = v2 & 0x1F
            r = v1 << cnt
            if cnt:
                flg = EFLG_SF | EFLG_ZF | EFLG_PF
                if cnt == 1:
                    flg |= EFLG_OF
                flags.CF = (r & 0x100) != 0
        elif opid == UD_Ishr:
            cnt = v2 & 0x1F
            r = v1 >> cnt
            if cnt:
                flg = EFLG_SF | EFLG_ZF | EFLG_PF
                if cnt == 1:
                    flg |= EFLG_OF
                flags.CF = (v1 & ( 1 << (cnt - 1))) != 0
        elif opid == UD_Isub:
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_CF | EFLG_PF
            r = v1 - v2
        elif opid == UD_Ixor:
            r = v1 | v2
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0

        if flg & EFLG_OF:
            flags.OF = (r & 0x80) != (v1 & 0x80)
        if flg & EFLG_CF:
            flags.CF = (r & 0xFF00) != 0
        if flg & EFLG_ZF:
            flags.ZF = (r & 0xFF) == 0
        if flg & EFLG_SF:
            flags.SF = (r & 0x80) != 0
        if flg & EFLG_PF:
            t = r & 0xFF
            t = ((r & 0xAA) >> 1) ^ (r & 0x55)
            t = ((t & 0x50) >> 4) ^ (t & 5)
            flags.PF = ((t >> 2) ^ (t & 1)) == 0
    elif sz == 16:
        v1 = UWORD(val1)
        v2 = UWORD(val2)
        r = 0
        flg = 0
        if opid == UD_Inot:
            pass
        elif opid == UD_Iadd:
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_CF | EFLG_PF
            r = v1 + v2
        elif opid == UD_Iand:
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0
            r = v1 & v2
        elif opid == UD_Idec:
            r = v1 - 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Iinc:
            r = v1 + 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Ineg:
            r = v1 + 1
            if v1 == 0:
                flags.CF = 0
            else:
                flags.CF = 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Ior:
            r = v1 | v2
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0
        elif opid == UD_Ishl:
            cnt = v2 & 0x1F
            r = v1 << cnt
            if cnt:
                flg = EFLG_SF | EFLG_ZF | EFLG_PF
                if cnt == 1:
                    flg |= EFLG_OF
                flags.CF = (r & 0x10000) != 0
        elif opid == UD_Ishr:
            cnt = v2 & 0x1F
            r = v1 >> cnt
            if cnt:
                flg = EFLG_SF | EFLG_ZF | EFLG_PF
                if cnt == 1:
                    flg |= EFLG_OF
                flags.CF = (v1 & (1 << (cnt - 1))) != 0
        elif opid == UD_Isub:
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_CF | EFLG_PF
            r = v1 - v2
        elif opid == UD_Ixor:
            r = v1 | v2
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0

        if flg & EFLG_OF:
            flags.OF = (r & 0x8000) != (v1 & 0x8000)
        if flg & EFLG_CF:
            flags.CF = (r & 0xFFFF0000) != 0
        if flg & EFLG_ZF:
            flags.ZF = (r & 0xFFFF) == 0
        if flg & EFLG_SF:
            flags.SF = (r & 0x8000) != 0
        if flg & EFLG_PF:
            t = r & 0xFFFF
            t = ((r & 0xAAAA) >> 1) ^ (r & 0x5555)
            t = ((r & 0x5500) >> 8) ^ (r & 0x55)
            t = ((t & 0x50) >> 4) ^ (t & 5)
            flags.PF = ((t >> 2) ^ (t & 1)) == 0
    elif sz == 32:
        v1 = UDWORD(val1)
        v2 = UDWORD(val2)
        r = 0
        flg = 0
        if opid == UD_Inot:
            pass
        elif opid == UD_Iadd:
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_CF | EFLG_PF
            r = v1 + v2
        elif opid == UD_Iand:
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0
            r = v1 & v2
        elif opid == UD_Idec:
            r = v1 - 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Iinc:
            r = v1 + 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Ineg:
            r = v1 + 1
            if v1 == 0:
                flags.CF = 0
            else:
                flags.CF = 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Ior:
            r = v1 | v2
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0
        elif opid == UD_Ishl:
            cnt = v2 & 0x1F
            r = v1 << cnt
            if cnt:
                flg = EFLG_SF | EFLG_ZF | EFLG_PF
                if cnt == 1:
                    flg |= EFLG_OF
                flags.CF = (r & 0x100000000) != 0
        elif opid == UD_Ishr:
            cnt = v2 & 0x1F
            r = v1 >> cnt
            if cnt:
                flg = EFLG_SF | EFLG_ZF | EFLG_PF
                if cnt == 1:
                    flg |= EFLG_OF
                flags.CF = (v1 & (1 << (cnt - 1))) != 0
        elif opid == UD_Isub:
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_CF | EFLG_PF
            r = v1 - v2
        elif opid == UD_Ixor:
            r = v1 | v2
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0

        if flg & EFLG_OF:
            flags.OF = (r & 0x80000000) != (v1 & 0x80000000)
        if flg & EFLG_CF:
            flags.CF = (r & 0xFFFFFFFF00000000) != 0
        if flg & EFLG_ZF:
            flags.ZF = (r & 0xFFFFFFFF) == 0
        if flg & EFLG_SF:
            flags.SF = (r & 0x80000000) != 0
        if flg & EFLG_PF:
            t = r & 0xFFFFFFFF
            t = ((r & 0xAAAAAAAA) >> 1) ^ (r & 0x55555555)
            t = ((r & 0x55550000) >> 16) ^ (r & 0x5555)
            t = ((r & 0x5500) >> 8) ^ (r & 0x55)
            t = ((t & 0x50) >> 4) ^ (t & 5)
            flags.PF = ((t >> 2) ^ (t & 1)) == 0
    elif sz == 64:
        v1 = UQDWORD(val1)
        v2 = UQDWORD(val2)
        r = 0
        flg = 0
        if opid == UD_Inot:
            pass
        elif opid == UD_Iadd:
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_CF | EFLG_PF
            r = v1 + v2
        elif opid == UD_Iand:
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0
            r = v1 & v2
        elif opid == UD_Idec:
            r = v1 - 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Iinc:
            r = v1 + 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Ineg:
            r = v1 + 1
            if v1 == 0:
                flags.CF = 0
            else:
                flags.CF = 1
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_PF
        elif opid == UD_Ior:
            r = v1 | v2
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0
        elif opid == UD_Ishl:
            cnt = v2 & 0x3F
            r = v1 << cnt
            if cnt:
                flg = EFLG_SF | EFLG_ZF | EFLG_PF
                if cnt == 1:
                    flg |= EFLG_OF
                flags.CF = (r & (1 << 64)) != 0
        elif opid == UD_Ishr:
            cnt = v2 & 0x3F
            r = v1 >> cnt
            if cnt:
                flg = EFLG_SF | EFLG_ZF | EFLG_PF
                if cnt == 1:
                    flg |= EFLG_OF
                flags.CF = (v1 & (1 << (cnt - 1))) != 0
        elif opid == UD_Isub:
            flg = EFLG_OF | EFLG_SF | EFLG_ZF | EFLG_AF | EFLG_CF | EFLG_PF
            r = v1 - v2
        elif opid == UD_Ixor:
            r = v1 | v2
            flg = EFLG_SF | EFLG_ZF | EFLG_PF
            flags.OF = 0
            flags.CF = 0

        if flg & EFLG_OF:
            flags.OF = (r & (1 << 63)) != (v1 & (1 << 63))
        if flg & EFLG_CF:
            flags.CF = (r & 0xFFFFFFFF0000000000000000) != 0
        if flg & EFLG_ZF:
            flags.ZF = (r & ((1 << 64) - 1)) == 0
        if flg & EFLG_SF:
            flags.SF = (r & (1 << 63)) != 0
        if flg & EFLG_PF:
            t = r & ((1 << 64) - 1)
            t = ((r & 0xAAAAAAAAAAAAAAAA) >> 1) ^ (r & 0x5555555555555555)
            t = ((r & 0x5555555500000000) >> 32) ^ (r & 0x55555555)
            t = ((r & 0x55550000) >> 16) ^ (r & 0x5555)
            t = ((r & 0x5500) >> 8) ^ (r & 0x55)
            t = ((t & 0x50) >> 4) ^ (t & 5)
            flags.PF = ((t >> 2) ^ (t & 1)) == 0


def EvaluateJcc(opid, flg):
	if opid == UD_Ija:
		return (not flg.CF) and (not flg.ZF)
	elif opid == UD_Ijb:
		return flg.CF != False
	elif opid == UD_Ijbe:
		return flg.CF or flg.ZF
	elif opid == UD_Ijz:
		return flg.ZF
	elif opid == UD_Ijg:
		return flg.SF == flg.OF and not flg.ZF
	elif opid == UD_Ijge:
		return flg.SF == flg.OF
	elif opid == UD_Ijl:
		return flg.SF != flg.OF
	elif opid == UD_Ijle:
		return flg.SF == flg.OF and not flg.ZF
	elif opid == UD_Ijae:
		return not flg.CF
	elif opid == UD_Ijno:
		return not flg.OF
	elif opid == UD_Ijnp:
		return not flg.PF
	elif opid == UD_Ijns:
		return not flg.SF
	elif opid == UD_Ijnz:
		return not flg.ZF
	elif opid == UD_Ijo:
		return flg.OF
	elif opid == UD_Ijp:
		return flg.PF
	elif opid == UD_Ijs:
		return flg.SF
	else:
		print("Error-DoMultiBranchJump got an unknown nID as parameter")
		return False


REG_NAMES = {UD_R_AL : "AL", UD_R_AH : "AH", UD_R_AX : "AX", UD_R_EAX : "EAX", UD_R_RAX : "RAX",
             UD_R_CL : "CL", UD_R_CH : "CH", UD_R_CX : "CX", UD_R_ECX : "ECX", UD_R_RCX : "RCX",
             UD_R_DL : "DL", UD_R_DH : "DH", UD_R_DX : "DX", UD_R_EDX : "EDX", UD_R_RDX : "RDX",
             UD_R_BL : "BL", UD_R_BH : "BH", UD_R_BX : "BX", UD_R_EBX : "EBX", UD_R_RBX : "RBX",
             UD_R_SPL : "SPL", UD_R_SP : "SP", UD_R_ESP : "ESP", UD_R_RSP : "RSP",
             UD_R_BPL : "BPL", UD_R_BP : "BP", UD_R_EBP : "EBP", UD_R_RBP : "RBP",
             UD_R_SIL : "SIL", UD_R_SI : "SI", UD_R_ESI : "ESI", UD_R_RSI : "RSI",
             UD_R_DIL : "DIL", UD_R_DI : "DI", UD_R_EDI : "EDI", UD_R_RDI : "RDI",
             UD_R_R8B : "R8B", UD_R_R8W : "R8W", UD_R_R8D : "R8D", UD_R_R8 : "R8",
             UD_R_R9B : "R9B", UD_R_R9W : "R9W", UD_R_R9D : "R9D", UD_R_R9 : "R9",
             UD_R_R10B : "R10B", UD_R_R10W : "R10W", UD_R_R10D : "R10D", UD_R_R10 : "R10",
             UD_R_R11B : "R11B", UD_R_R11W : "R11W", UD_R_R11D : "R11D", UD_R_R11 : "R11",
             UD_R_R12B : "R12B", UD_R_R12W : "R12W", UD_R_R12D : "R12D", UD_R_R12 : "R12",
             UD_R_R13B : "R13B", UD_R_R13W : "R13W", UD_R_R13D : "R13D", UD_R_R13 : "R13",
             UD_R_R14B : "R14B", UD_R_R14W : "R14W", UD_R_R14D : "R14D", UD_R_R14 : "R14",
             UD_R_R15B : "R15B", UD_R_R15W : "R15W", UD_R_R15D : "R15D", UD_R_R15 : "R15"}

def udRegName(reg):
    return REG_NAMES.get(reg, "R_V{:x}".format(reg))

def udFamilyRegName(fam, sz):
    reg = udFamilyReg(fam, sz)
    if reg == UD_NONE:
        szn = {8: "B", 16: "W", 32: "D", 64: "Q"}
        return "R_V{:x}{}".format(fam, szn[sz])
    else:
        return REG_NAMES[reg]