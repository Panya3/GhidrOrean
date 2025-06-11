import opcode
import time
from operator import truediv


import xrkdsm
from xrkutil import *
from xrkdsm import *
from thobfus import *
from xrkasm import *
from thvm import *
from thwild86 import *
from __main__ import *


TKEY_OPR1_32 = 3  #VM register index for operator 1 (32bit)
TKEY_OPR1_16 = 5  #VM register index for operator 1 (16bit)
TKEY_OPR0 = 6  #VM register index for operator 0

TKEY_OPERAND0 = (TKEY_OPR0, )
TKEY_OPERAND1 = (TKEY_OPR1_16, TKEY_OPR1_32)

TH_NOP = 0x2000 #

TH_PUSH = 0x2001
TH_POP = 0x2002 #

TH_INC = 0x2003 #
TH_DEC = 0x2004 #
TH_NOT = 0x2005 #
TH_NEG = 0x2006 #

TH_MOV = 0x2007 #
TH_MOVSX = 0x2008 #
TH_MOVZX = 0x2009 #

TH_ADD = 0x200a #
TH_SUB = 0x200b #
TH_AND = 0x200c #
TH_XOR = 0x200d #
TH_OR = 0x200e #

TH_SHL = 0x200f #
TH_SHR = 0x2010 #
TH_RCL = 0x2011 #
TH_RCR = 0x2012 #
TH_ROL = 0x2013 #
TH_ROR = 0x2014 #

TH_CMP = 0x2015 #
TH_TEST = 0x2016 #

TH_IMUL = 0x2017

TH_COUNT = 0x2018

TH_UNSHUFLE = 0x2019

TH_IMGBASE = 0x201A


THOP_UNSHUFFLE = 0x1100


TIGER_OPTXT = {THOP_UNSHUFFLE: "UNSHUFFLE"}

class REGTRACE:
    Key = -1
    Off = -1
    KeySz = 0
    DataTp = 0
    VmImg = False
    # 1 - reg
    # 2 - val
    # 3 - valmem
    # 4 - regmem



class TG_CTX_OP:
    isFound = False
    data = 0
    info = 0

class TG_OP_DEC:
    mnem = 0
    sz = 0
    data = 0

    def __init__(self, a=0, b=0, c=0):
        self.mnem = a
        self.sz = b
        self.data = c

class TG_OP:
    tp = 0
    sz = 0
    wrksz = 0
    idx = 0
    decoders = None
    tkey = -1
    flags = 0
    usei = -1
    useopr = -1

    def __init__(self):
        self.decoders = []

class THNDL(WHNDL):
    operands = None
    addr = 0
    opidx = -1

    def __init__(self, id = -1):
        WHNDL.__init__(self, id)
        self.operands = [TG_OP(), TG_OP()]

class TIGER(WILD):
    tigerOperands = None

    def __init__(self, bits, d):
        WILD.__init__(self, bits, WILD_TIGER, d)
        self.HANDLER = THNDL

        self.tigerOperands = [TG_CTX_OP(), TG_CTX_OP()]


    def CheckForKeysHandle(self):
        if CMDSimpler.count < 8:
            return False

        types = ((UD_OP_MEM, 32), (UD_OP_MEM, 32), (UD_OP_MEM, 32), (UD_OP_MEM, 32), (UD_OP_MEM, 32),\
                 (UD_OP_MEM, 16), (UD_OP_MEM, 16), (UD_OP_MEM, 16), (UD_OP_MEM, 32), (UD_OP_MEM, 32))

        for i in range(len(types)):
            op = CMDSimpler.heap[i].instr

            if op.mnemonic == UD_Imov and op.operand[0].TSZ() == types[i] and\
               op.operand[0].BIS() in ((UD_R_EBP, UD_NONE, 0), (UD_R_RBP, UD_NONE, 0)) and\
               op.operand[1].type == UD_OP_IMM and op.operand[1].lval.lval == 0:
                self.AddKey(op.operand[0].lval.lval)
            else:
                return False
        return True

    def FindOperandKeyReadIns(self, opkey, idx):
        for i in range(idx, CMDSimpler.count):
            op = CMDSimpler.heap[i].instr

            for opk in opkey:
                if (op.mnemonic == UD_Imovzx or (opk == TKEY_OPR1_32 and op.mnemonic == UD_Imov))  and op.operand[0].type == UD_OP_REG and \
                   op.operand[1].type == UD_OP_MEM and \
                   op.operand[1].base in (UD_R_EBP, UD_R_RBP) and \
                   op.operand[1].index == UD_NONE and \
                   op.operand[1].scale == 0 and \
                   op.operand[1].lval.lval == self.GetKeyOffset(opk):
                    return (i, op)
        return (-1, None)

    def MapUnaryOperation(self, h, opid):

        i = 0
        while i < CMDSimpler.count:
            (ti, top) = self.FindOperandKeyReadIns( TKEY_OPERAND0, i)
            isop1 = False
            if ti == -1:
                if opid == UD_Ipush:
                    (ti, top) = self.FindOperandKeyReadIns(TKEY_OPERAND1, i)
                    isop1 = True

                if ti == -1:
                    i += 1
                    continue

            i = ti
            optp = TH_OPR_REG
            stg = 0
            for j in range(i + 1, CMDSimpler.count):
                jop = CMDSimpler.heap[j].instr
                if stg == 0 and \
                    jop.mnemonic == UD_Iadd and \
                    jop.operand[0].type == UD_OP_REG and\
                    jop.operand[0].base == top.operand[0].base and \
                    jop.operand[1].type == UD_OP_REG and \
                    jop.operand[1].base in (UD_R_EBP, UD_R_RBP):
                    stg += 1
                elif stg == 1:
                    if jop.mnemonic == UD_Imov and \
                        jop.operand[0].type == UD_OP_REG and\
                        jop.operand[0].base == top.operand[0].base:
                        if jop.operand[1].TSZ() == (UD_OP_MEM, 32) and \
                           jop.operand[1].base == top.operand[0].base:
                            optp = TH_OPR_MEM_IMM
                        else:
                            break
                    elif jop.mnemonic == opid and \
                        jop.operand[0].type == UD_OP_MEM and\
                        jop.operand[0].base == top.operand[0].base:
                        h.addr = CMDSimpler.heap[j].addr
                        h.operands[0].tp = optp
                        h.operands[0].sz = jop.operand[0].size
                        h.operands[0].idx = ti
                        h.operands[0].tkey = TKEY_OPR0

                        return j

                elif isop1 and stg == 0 and opid == UD_Ipush and \
                    jop.mnemonic == opid and \
                    jop.operand[0].type == UD_OP_REG and \
                    jop.operand[0].base == top.operand[0].base:
                    h.addr = CMDSimpler.heap[j].addr
                    h.operands[0].tp = TH_OPR_MEM_IMM
                    h.operands[0].sz = jop.operand[0].size
                    h.operands[0].idx = ti
                    if isop1:
                        if top.operand[1].lval.lval == self.GetKeyOffset(TKEY_OPR1_32):
                            h.operands[0].tkey = TKEY_OPR1_32
                        else:
                            h.operands[0].tkey = TKEY_OPR1_16
                    else:
                        h.operands[0].tkey = TKEY_OPR0

                    return j

            i += 1
        return -1


    def FindOperand1VMSource(self, i, opt):
        op = CMDSimpler.heap[i].instr
        reg = op.operand[opt].Family()

        # not xSP/xBP
        if reg in (UD_R_FAMILY_SP, UD_R_FAMILY_BP) or i <= 0:
            return (-1, 0, 0, 0)

        j = i - 1
        tp = TH_OPR_IMM
        cnt = 0
        movop = 0
        while j > -1:
            opj = CMDSimpler.heap[j].instr

            if opj.mnemonic in (UD_Imov, UD_Imovsx, UD_Imovzx):
                if opj.operand[0].type == UD_OP_REG and opj.operand[0].Family() == reg:
                    if opj.operand[1].type == UD_OP_REG:
                        if opj.operand[1].base not in (UD_R_ESP, UD_R_EBP, UD_R_RSP, UD_R_RBP):
                            reg = opj.operand[1].Family()
                            if cnt == 0 and opj.mnemonic in (UD_Imovsx, UD_Imovzx):
                                movop = opj.mnemonic
                        else:
                            xlog("Something wrong! It's must not happen.")
                            return (-1, 0, 0, 0)
                    elif opj.operand[1].type == UD_OP_MEM:
                        if opj.operand[1].base in (UD_R_EBP, UD_R_RBP):
                            if opj.operand[1].lval.lval == self.GetKeyOffset(TKEY_OPR1_16):
                                return (j, tp, movop, TKEY_OPR1_16)
                            elif opj.operand[1].lval.lval == self.GetKeyOffset(TKEY_OPR1_32):
                                return (j, tp, movop, TKEY_OPR1_32)
                            else:
                                return (-1, 0, 0, 0)
                        else:
                            reg = opj.operand[1].Family()
                            cnt += 1
                            if cnt >= 2:
                                tp = TH_OPR_MEM_IMM
                            elif movop == 0:
                                movop = opj.mnemonic
            elif opj.mnemonic == UD_Iadd and\
                cnt == 1 and\
                opj.operand[0].type == UD_OP_REG and\
                opj.operand[0].size in (32, 64) and\
                opj.operand[0].Family() == reg and\
                opj.operand[1].type == UD_OP_REG and\
                opj.operand[1].base in (UD_R_EBP, UD_R_RBP):
                tp = TH_OPR_REG

            j -= 1
        return (-1, 0, 0, 0)

    def MapBinOperation(self, h, idx, opid, dbg = False):
        opKeyIns = None
        i = 0
        while i < CMDSimpler.count:
            (ti, top) = self.FindOperandKeyReadIns(TKEY_OPERAND0, i)
            if ti == -1:
                i += 1
                continue

            topreg = top.operand[0].base

            i = ti
            op0tp = TH_OPR_REG
            stg = 0
            sepidx = -1
            sepreg = -1
            mreg = -1
            for j in range(i + 1, CMDSimpler.count):
                jop = CMDSimpler.heap[j].instr
                if stg == 0 and \
                   jop.mnemonic == UD_Iadd and \
                   jop.operand[0].type == UD_OP_REG and\
                   jop.operand[0].base == topreg and \
                   jop.operand[1].type == UD_OP_REG and\
                   jop.operand[1].base in (UD_R_EBP, UD_R_RBP):
                    stg += 1
                    if dbg:
                        xlog("stg +1 at {:x}".format(CMDSimpler.heap[j].addr))
                elif stg == 1:
                    if jop.mnemonic == UD_Imov and \
                       jop.operand[0].type == UD_OP_REG and\
                       jop.operand[0].base == topreg:
                        if jop.operand[1].TSZ() == (UD_OP_MEM, 32) and\
                           jop.operand[1].base == topreg:
                            op0tp = TH_OPR_MEM_IMM
                        else:
                            break
                    elif jop.mnemonic == UD_Imov and jop.operand[0].type == UD_OP_REG and \
                         jop.operand[1].TSZ() == (UD_OP_MEM, 32) and jop.operand[1].BISO() == (topreg, UD_NONE, 0, 0 ):
                        sepreg = jop.operand[0].Family()
                        if dbg:
                            xlog("sepreg", sepreg)
                    elif jop.mnemonic == UD_Imov and jop.operand[0].type == UD_OP_REG and jop.operand[0].Family() == udBaseFamily(topreg):
                        if dbg:
                            xlog("break MOV reg at {:x}".format(CMDSimpler.heap[j].addr))
                        break
                    elif jop.mnemonic == UD_Imov and jop.operand[0].type == UD_OP_REG and \
                         jop.operand[1].type == UD_OP_REG and jop.operand[1].base == topreg:
                        topreg = jop.operand[0].base
                    elif jop.mnemonic == opid and \
                        jop.operand[0].type == UD_OP_MEM and\
                        jop.operand[0].base == topreg:

                        (op1i, op1tp, movop, t1key) = self.FindOperand1VMSource(j, 1)

                        #if opid == OP_RCR:
                        #    xlog("RCR", op1i, op1tp, movop, t1key)

                        if op1i == -1:
                            break

                        h.addr = CMDSimpler.heap[j].addr
                        h.operands[0].tp = op0tp
                        h.operands[0].sz = jop.operand[0].size
                        h.operands[0].idx = i
                        h.operands[0].tkey = TKEY_OPR0
                        h.operands[1].tp = op1tp
                        h.operands[1].sz = jop.operand[1].size
                        h.operands[1].wrksz = CMDSimpler.heap[op1i].instr.operand[1].size
                        h.operands[1].idx = op1i
                        h.operands[1].tkey = t1key

                        return j
                    elif sepreg != -1 and jop.mnemonic == opid and \
                         jop.operand[0].type == UD_OP_REG and \
                         jop.operand[0].Family() == sepreg:
                        sepidx = j
                    elif sepreg != -1 and sepidx != -1 and \
                         j - sepidx < 5 and\
                        jop.mnemonic == UD_Imov and \
                        jop.operand[0].type == UD_OP_MEM and\
                        jop.operand[0].base == topreg:

                        (op1i, op1tp, movop, t1key) = self.FindOperand1VMSource(sepidx, 1)
                        if op1i == -1:
                            break

                        h.addr = CMDSimpler.heap[j].addr
                        h.operands[0].tp = op0tp
                        h.operands[0].sz = jop.operand[0].size
                        h.operands[0].idx = i
                        h.operands[0].tkey = TKEY_OPR0
                        h.operands[1].tp = op1tp
                        h.operands[1].sz = jop.operand[1].size
                        h.operands[1].wrksz = CMDSimpler.heap[op1i].instr.operand[1].size
                        h.operands[1].idx = op1i
                        h.operands[1].tkey = t1key

                        return j
                    elif jop.mnemonic == UD_Imov and opid in (UD_Imovsx, UD_Imovzx) and jop.operand[0].type == UD_OP_MEM and \
                            jop.operand[0].base == topreg:

                        jj = j - 1
                        while jj > -1:
                            jjop = CMDSimpler.heap[jj].instr
                            if jjop.mnemonic == opid and \
                               jjop.operand[0].type == UD_OP_REG and jjop.operand[0].Family() == jop.operand[1].Family():
                                break
                            jj -= 1

                        (op1i, op1tp, movop, t1key) = self.FindOperand1VMSource(j, 1)

                        if op1i == -1 or movop != opid:
                            break

                        h.addr = CMDSimpler.heap[j].addr
                        h.operands[0].tp = op0tp
                        h.operands[0].sz = jop.operand[1].size
                        h.operands[0].idx = i
                        h.operands[0].tkey = TKEY_OPR0
                        h.operands[1].tp = op1tp
                        h.operands[1].sz = CMDSimpler.heap[jj].instr.operand[1].size
                        h.operands[1].wrksz = CMDSimpler.heap[op1i].instr.operand[1].size
                        h.operands[1].idx = op1i
                        h.operands[1].tkey = t1key
                        if jj != -1:
                            h.operands[1].usei = jj
                            h.operands[1].useopr = 1

                        return j
            i += 1
        return -1


    # def FindReaders(self, h):
    #     lst = list()
    #     reg = -1
    #     off = -1
    #     for i in range(CMDSimpler.count):
    #         op = CMDSimpler.heap[i].instr
    #         if op.ID == OP_MOV and self.IsVmEipOp(op) and op.operand[0].ID == ID_REG:
    #             reg = op.operand[0].Base()
    #             off = -1
    #         elif reg != -1 and op.ID == OP_ADD and op.operand[0].IsReg(reg) and \
    #             op.operand[1].TID() == TID_VAL:
    #             off = op.operand[1].value
    #         elif op.ID == OP_MOV op.operand[0]

    def FindSourceReadOff(self, i, family):
        lst = self.BacktraceReg(i, family)
        if len(lst) == 0:
            xlog("ESP backtrace not found")
            return (-1, -1)

        bi = lst[-1]
        sop = CMDSimpler.heap[bi].instr
        if sop.mnemonic not in (UD_Imov, UD_Imovzx):
            xlog("not get offsrc")
            return (-1, -1)

        lst = self.BacktraceReg(bi, sop.operand[1].Family())
        if len(lst) == 0:
            xlog("no offsrc backtrace found")
            return (-1, -1)

        if len(lst) < 2:
            return (-1, -1)

        fop = CMDSimpler.heap[lst[-1]].instr
        if fop.mnemonic not in (UD_Imov, UD_Imovzx) or not self.IsVmEipOp(fop):
            return (-1, -1)

        for j in lst:
            jop = CMDSimpler.heap[j].instr
            if jop.mnemonic == UD_Iadd and \
                jop.operand[1].type == UD_OP_IMM:
                off = jop.operand[1].lval.lval
                if off > 0x100:
                    xlog("ERROR off > 0x100")
                    return (-1, -1)
                return (off, sop.operand[0].size)
        return (-1, -1)

    def TraceListAddr(self, i, opid):
        lst = list()
        family = CMDSimpler.heap[i].instr.operand[opid].Family()
        i -= 1
        while i >= 0:
            op = CMDSimpler.heap[i].instr

            if IsOpClass(op.mnemonic, 0, 0, 1) and \
                op.operand[0].type == UD_OP_REG and op.operand[0].Family() == family and \
                op.operand[1].type == UD_OP_IMM:
                lst.append((i, op))
            elif op.mnemonic == UD_Iadd and \
               op.operand[0].type == UD_OP_REG and op.operand[0].Family() == family:
                if op.operand[1].type == UD_OP_REG and\
                   op.operand[1].base in (UD_R_EBP, UD_R_RBP):
                    lst.append((i, op))
                elif op.operand[1].TSZ() == (UD_OP_MEM, 32) and \
                     op.operand[1].base in (UD_R_EBP, UD_R_RBP) and op.operand[1].lval.lval == self.vmImgBaseOffset:
                    lst.append((i, op))
            elif op.mnemonic in (UD_Imov, UD_Imovzx) and \
               op.operand[0].type == UD_OP_REG and op.operand[0].Family() == family:
                if op.operand[1].type == UD_OP_REG:
                    family = op.operand[1].Family()
                    lst.append((i, op))
                elif op.operand[1].type == UD_OP_MEM:
                    if op.operand[1].base in (UD_R_EBP, UD_R_RBP):
                        lst.append((i, op))
                        break
                    elif op.operand[1].base not in (UD_R_ESP, UD_R_RSP) and \
                         op.operand[1].index == UD_NONE and op.operand[1].scale == 0 and op.operand[1].lval.lval == 0:
                        family = op.operand[1].Family()
                        lst.append((i, op))
                    else:
                        break
                else:
                    break
            i -= 1
        return lst


    def TraceAddr(self, i, opid):
        family = CMDSimpler.heap[i].instr.operand[opid].Family()
        isreg = False
        useImgBase = False
        off = -1
        deref = 0
        keyval = -1
        lastSz = 0
        i -= 1
        while i >= 0:
            op = CMDSimpler.heap[i].instr

            if op.mnemonic == UD_Iadd and \
               op.operand[0].type == UD_OP_REG and op.operand[0].Family() == family:
                if op.operand[1].type == UD_OP_REG and\
                   op.operand[1].base in (UD_R_EBP, UD_R_RBP):
                    isreg = True
                elif op.operand[1].TSZ() == (UD_OP_MEM, 32) and \
                     op.operand[1].base in (UD_R_EBP, UD_R_RBP) and op.operand[1].lval.lval == self.vmImgBaseOffset:
                    useImgBase = True
                elif op.operand[1].type == UD_OP_IMM:
                    off = op.operand[1].lval.lval
            elif op.mnemonic in (UD_Imov, UD_Imovzx) and \
               op.operand[0].type == UD_OP_REG and op.operand[0].Family() == family:
                if op.operand[1].type == UD_OP_REG:
                    family = op.operand[1].Family()
                    lastSz = op.operand[1].size
                elif op.operand[1].type == UD_OP_MEM:
                    if op.operand[1].base in (UD_R_EBP, UD_R_RBP):
                        keyval = op.operand[1].lval.lval
                        break
                    elif op.operand[1].base not in (UD_R_ESP, UD_R_RSP) and \
                         op.operand[1].index == UD_NONE and op.operand[1].scale == 0 and op.operand[1].lval.lval == 0:
                        deref += 1
                        family = op.operand[1].Family()
                        lastSz = op.operand[1].size
                    else:
                        return REGTRACE()
                else:
                    break
            i -= 1

        res = REGTRACE()
        res.Key = keyval
        if useImgBase:
            res.VmImg = 1
        res.Off = off
        res.KeySz = lastSz
        if isreg:
            if deref == 2:
                res.DataTp = TH_OPR_REG # CALL REG
            elif deref == 3:
                res.DataTp = TH_OPR_MEM_REG
        else:
            if deref == 1:
                res.DataTp = TH_OPR_IMM
            elif deref == 2:
                res.DataTp = TH_OPR_MEM_IMM
        return res



    def CheckHndlTCall(self, h):
        heap = CMDSimpler.heap
        if heap[ CMDSimpler.count - 1 ].instr.mnemonic == UD_Iret:
            lst = list()

            espReg = -1
            espOff = -1
            espOffSz = 0
            addr1 = None
            addr2 = None
            addrOff2 = -1
            for i in range(CMDSimpler.count):
                op = heap[i].instr
                if op.mnemonic == UD_Iadd and \
                        op.operand[0].type == UD_OP_REG and \
                        op.operand[1].type == UD_OP_REG and \
                        op.operand[1].base in (UD_R_ESP, UD_R_RSP):
                    espReg = op.operand[0].base
                    espOff, espOffSz = self.FindSourceReadOff(i - 1, op.operand[0].Family())
                elif espOff != -1:
                    if op.mnemonic == UD_Imov and \
                       op.operand[0].TSZ() == (UD_OP_MEM, 32) and op.operand[0].base == espReg and \
                       op.operand[1].type == UD_OP_REG:
                        if addr1 == None:
                            addr1 = self.TraceAddr(i, 1)
                        else:
                            addr2 = self.TraceAddr(i, 1)
                            break
                    elif op.mnemonic in (UD_Imov, UD_Imovzx, UD_Imovsx) and \
                        op.operand[0].type == UD_OP_REG and op.operand[0].Family() == udBaseFamily(espReg):
                        break
                    elif op.mnemonic == UD_Iadd and \
                        op.operand[0].type == UD_OP_REG and op.operand[0].Family() == udBaseFamily(espReg) and \
                        op.operand[1].type == UD_OP_IMM:
                        addrOff2 = op.operand[1].lval.lval

            # h.operands[0].tp = TH_OPR_UNK
            #
            # if CMDSimpler.Bounds(3) and \
            #     heap[2].instr.operand[1].Size() == 3 and \
            #     heap[3].instr.operand[1].IsMem32Base(R_EBP)and \
            #     heap[3].instr.operand[1].val2 == self.vmImgBaseOffset:
            #     #xlog("OFF", hex(self.vmImgBaseOffset))
            #     h.operands[0].tp = TH_OPR_IMM
            # elif CMDSimpler.Bounds(4) and \
            #     heap[4].instr.ID == OP_MOV and heap[4].instr.operand[1].ID == ID_MEM32:
            #         #xlog("OKLOL")
            #         if CMDSimpler.Bounds(5) and \
            #             heap[5].instr.ID == OP_MOV and \
            #             heap[5].instr.operand[1].IsMem32Base( heap[4].instr.operand[0].Base() ):
            #             h.operands[0].tp = TH_OPR_MEM
            #         else:
            #             h.operands[0].tp = TH_OPR_REG

            if addr1 != None and addr1.DataTp != 0:
                h.operands[0].tp = addr1.DataTp
                h.operands[0].sz = addr1.KeySz
                h.operands[0].flags = addr1.VmImg
                h.opcodeOffsets[0] = addr1.Off

            if addr2 != None and addr2.DataTp != 0:
                h.operands[1].tp = addr2.DataTp
                h.operands[1].sz = addr2.KeySz
                h.operands[1].flags = addr2.VmImg
                h.opcodeOffsets[1] = addr2.Off

            h.tp = WH_CALL
            #xlog("CALLLLLLLLLL")
            #exit(0)
            return True
        return False

    def CheckHndlTNop(self, h):
        if h.flowReadIndex == 0:
            h.tp = TH_NOP
            return True
        return False


    def CheckHndlTPush(self, h):
        idx = self.MapUnaryOperation(h, UD_Ipush)
        if idx == -1:
            return False

        if CMDSimpler.Bounds(idx, 1) and\
            CMDSimpler.heap[idx + 1].instr.mnemonic not in (UD_Ipopfw, UD_Ipopfd, UD_Ipopfq):
            h.tp = TH_PUSH
            h.opidx = idx
            #xlog("PUSH")
            return True
        return False

    def CheckHndlTPop(self, h):
        idx = self.MapUnaryOperation(h, UD_Ipop)
        if idx == -1:
            return False

        h.tp = TH_POP
        h.opidx = idx
        # xlog("POP")
        return True

    def CheckHndlTInc(self, h):
        idx = self.MapUnaryOperation(h,  UD_Iinc)
        if idx == -1:
            return False

        h.tp = TH_INC
        h.opidx = idx
        #xlog("INC")
        return True

    def CheckHndlTDec(self, h):
        idx = self.MapUnaryOperation(h,  UD_Idec)
        if idx == -1:
            return False

        h.tp = TH_DEC
        h.opidx = idx
        #xlog("DEC")
        return True

    def CheckHndlTNot(self, h):
        idx = self.MapUnaryOperation(h,  UD_Inot)
        if idx == -1:
            return False

        h.tp = TH_NOT
        h.opidx = idx
        #xlog("NOT")
        return True

    def CheckHndlTNeg(self, h):
        idx = self.MapUnaryOperation(h, UD_Ineg)
        if idx == -1:
            return False

        h.tp = TH_NEG
        h.opidx = idx
        #xlog("NEG")
        return True

    def CheckHndlTMov(self, h):
        idx = self.MapBinOperation(h, 0, UD_Imov)
        if idx == -1:
            return False

        h.tp = TH_MOV
        h.opidx = idx
        #xlog("MOV")
        return True

    def CheckHndlTMovsx(self, h):
        idx = self.MapBinOperation(h, 0, UD_Imovsx)
        if idx == -1:
            return False

        h.tp = TH_MOVSX
        h.opidx = idx
        #xlog("MOVSX")
        return True

    def CheckHndlTMovzx(self, h):
        idx = self.MapBinOperation(h, 0, UD_Imovzx)
        if idx == -1:
            return False

        h.tp = TH_MOVZX
        h.opidx = idx
        #xlog("MOVZX")
        return True

    def CheckHndlTAdd(self, h):
        idx = self.MapBinOperation(h, 0, UD_Iadd)
        if idx == -1:
            return False

        h.tp = TH_ADD
        h.opidx = idx
        #xlog("ADD")
        return True

    def CheckHndlTSub(self, h):
        idx = self.MapBinOperation(h, 0, UD_Isub)
        if idx == -1:
            return False

        h.tp = TH_SUB
        h.opidx = idx
        #xlog("MOV")
        return True

    def CheckHndlTAnd(self, h):
        idx = self.MapBinOperation(h, 0, UD_Iand)
        if idx == -1:
            return False

        h.tp = TH_AND
        h.opidx = idx
        #xlog("AND")
        return True

    def CheckHndlTXor(self, h):
        idx = self.MapBinOperation(h, 0, UD_Ixor)
        if idx == -1:
            return False

        h.tp = TH_XOR
        h.opidx = idx
        #xlog("XOR")
        return True

    def CheckHndlTOr(self, h):
        idx = self.MapBinOperation(h, 0, UD_Ior)
        if idx == -1:
            return False

        h.tp = TH_OR
        h.opidx = idx
        #xlog("OR")
        return True

    def CheckHndlTShl(self, h):
        idx = self.MapBinOperation(h, 0, UD_Ishl)
        if idx == -1:
            return False

        h.tp = TH_SHL
        h.opidx = idx
        #xlog("SHL")
        return True

    def CheckHndlTShr(self, h):
        idx = self.MapBinOperation(h, 0, UD_Ishr)
        if idx == -1:
            return False

        h.tp = TH_SHR
        h.opidx = idx
        #xlog("SHR")
        return True

    def CheckHndlTRcl(self, h):
        idx = self.MapBinOperation(h, 0, UD_Ircl)
        if idx == -1:
            return False

        h.tp = TH_RCL
        h.opidx = idx
        #xlog("RCL")
        return True

    def CheckHndlTRcr(self, h):
        idx = self.MapBinOperation(h, 0, UD_Ircr)
        if idx == -1:
            return False

        h.tp = TH_RCR
        h.opidx = idx
        #xlog("RCR")
        return True

    def CheckHndlTRol(self, h):
        idx = self.MapBinOperation(h, 0, UD_Irol)
        if idx == -1:
            return False

        h.tp = TH_ROL
        h.opidx = idx
        #xlog("ROL")
        return True

    def CheckHndlTRor(self, h):
        idx = self.MapBinOperation(h, 0, UD_Iror)
        if idx == -1:
            return False

        h.tp = TH_ROR
        h.opidx = idx
        #xlog("ROR")
        return True

    def CheckHndlTCmp(self, h):
        idx = self.MapBinOperation(h, 0, UD_Icmp)
        if idx == -1:
            return False

        h.tp = TH_CMP
        h.opidx = idx
        #xlog("CMP")
        return True

    def CheckHndlTTest(self, h):
        idx = self.MapBinOperation(h, 0, UD_Itest)
        if idx == -1:
            return False

        h.tp = TH_TEST
        h.opidx = idx
        #xlog("TEST")
        return True

    def CheckHndlTImul(self, h):
        idx = self.MapBinOperation(h, 0, UD_Iimul)
        if idx == -1:
            return False

        h.tp = TH_IMUL
        h.opidx = idx
        #xlog("IMUL")
        return True

    def CheckHndlUnshuffle(self, h):
        heap = CMDSimpler.heap
        j = 0
        for i in range(6):
            op0 = heap[j + 0].instr
            op1 = heap[j + 1].instr
            op2 = heap[j + 2].instr
            op3 = heap[j + 3].instr
            op4 = heap[j + 4].instr
            if not (op0.mnemonic == UD_Imov and \
                op1.mnemonic == UD_Iadd and \
                op2.mnemonic == UD_Imov and \
                op3.mnemonic == UD_Iadd and \
                op4.mnemonic == UD_Ipush):
                return False
            j += 5
        for i in range(6):
            op0 = heap[j + 0].instr
            op1 = heap[j + 1].instr
            op2 = heap[j + 2].instr
            op3 = heap[j + 3].instr
            op4 = heap[j + 4].instr
            if not (op0.mnemonic == UD_Imov and \
                op1.mnemonic == UD_Iadd and \
                op2.mnemonic == UD_Imov and \
                op3.mnemonic == UD_Iadd and \
                op4.mnemonic == UD_Ipop):
                return False
            j += 5
        for i in range(12):
            h.opcodeOffsets[i] = heap[1 + i * 5].instr.operand[1].lval.lval
        h.tp = TH_UNSHUFLE
        h.opidx = 59
        return True

    def CheckHndlAddImgBase(self, h):
        opKeyIns = None
        i = 0
        while i < CMDSimpler.count:
            (ti, top) = self.FindOperandKeyReadIns(TKEY_OPERAND0, i)
            if ti == -1:
                i += 1
                continue

            i = ti
            stg = 0
            for j in range(i + 1, CMDSimpler.count):
                jop = CMDSimpler.heap[j].instr
                if stg == 0 and \
                        jop.mnemonic == UD_Iadd and \
                        jop.operand[0].type == UD_OP_REG and \
                        jop.operand[0].base == top.operand[0].base and \
                        jop.operand[1].type == UD_OP_REG and \
                        jop.operand[1].base in (UD_R_EBP, UD_R_RBP):
                    stg += 1
                elif stg == 1:
                    if jop.mnemonic == UD_Imov and jop.operand[0].type == UD_OP_REG and \
                        jop.operand[0].base == top.operand[0].base and \
                        (jop.operand[1].TSZ() != (UD_OP_MEM, 32) or jop.operand[1].base != top.operand[0].base):
                        break
                    elif jop.mnemonic == UD_Iadd and \
                            jop.operand[0].type == UD_OP_MEM and \
                            jop.operand[0].base == top.operand[0].base:

                        lst = self.TraceListAddr(j, 1)
                        if len(lst) == 1 and lst[0][1].operand[1].type == UD_OP_MEM and lst[0][1].operand[1].lval.lval == self.vmImgBaseOffset:
                            h.addr = CMDSimpler.heap[j].addr
                            h.tp = TH_IMGBASE
                            h.operands[0].tp = TH_OPR_REG
                            h.operands[0].sz = 32
                            h.operands[0].idx = ti
                            h.operands[0].tkey = TKEY_OPR0
                            h.opidx = j
                            return True
                        else:
                            break
            i += 1
        return False

    def DecryptTigerOperandData(self, h, opr):
        ops = TKEY_OPERAND0
        if opr == 1:
            ops = TKEY_OPERAND1

        (idx, top) = self.FindOperandKeyReadIns(ops, 0)
        if idx != -1:
            xlog(idx, OpTxt(top))
            idx += 1
            while CMDSimpler.Bounds(idx):
                op = CMDSimpler.heap[idx].instr
                if IsOpClass(op.mnemonic, 0, 0, 1) and\
                    op.operand[0].type == UD_OP_REG and \
                    op.operand[0].Family() == top.operand[0].Family() and\
                    op.operand[1].type == UD_OP_IMM:
                    xlog("Decoder {:d} {} {:d} {:x}".format(opr, OpTxt(op), op.operand[1].size, op.operand[1].lval.lval))
                    h.operands[opr].decoders.append( TG_OP_DEC(op.mnemonic, op.operand[1].size, op.operand[1].lval.lval) )
                else:
                    xlog("break {:d} {} {:d} {:x}".format(opr, OpTxt(op), op.operand[1].size, op.operand[1].lval.lval))
                    break
                idx += 1
        return True

    def BacktraceReg(self, i, xbase):
        lst = list()
        while i >= 0:
            op = CMDSimpler.heap[i].instr
            if IsOpClass(op.mnemonic, 0, 1, 1) and\
                op.operand[0].type == UD_OP_REG and op.operand[0].Family() == xbase:
                lst.append(i)
            elif op.mnemonic in (UD_Imov, UD_Imovzx) and \
                op.operand[0].type == UD_OP_REG and op.operand[0].Family() == xbase and \
                op.operand[1].type == UD_OP_MEM:
                lst.append(i)
                break
            elif op.mnemonic in (UD_Imov, UD_Imovzx) and \
                op.operand[0].type == UD_OP_REG and op.operand[0].Family() == xbase and \
                op.operand[1].type == UD_OP_REG:
                xbase = op.operand[1].Family()
            i -= 1
        return lst

    def DecryptTigerOperandDataMy(self, h, opr):
        if h.opidx == -1:
            return True

        op = CMDSimpler.heap[h.opidx].instr
        if h.operands[opr].idx != 0:
            lst = self.BacktraceReg(h.opidx - 1, op.operand[opr].Family())

            while True:
                if len(lst) == 1:
                    lop = CMDSimpler.heap[lst[0]].instr
                    if lop.mnemonic == UD_Imov and lop.operand[1].type == UD_OP_MEM and lop.operand[1].base not in (UD_R_EBP, UD_R_RBP):
                        lst = self.BacktraceReg(lst[0] - 1, lop.operand[1].Family())
                    else:
                        break
                else:
                    break

            for d in reversed(lst):
                dop = CMDSimpler.heap[d].instr
                if IsOpClass(dop.mnemonic, 0, 0, 1) and \
                    dop.operand[1].type == UD_OP_IMM:
                    h.operands[opr].decoders.append( TG_OP_DEC(dop.mnemonic, dop.operand[1].size, dop.operand[1].lval.lval) )
        return True

    def DecryptTigerOperandDataMy2(self, h, opr):
        if h.opidx == -1:
            return True

        opidx = h.opidx
        opn = opr
        if h.operands[opr].usei != -1:
            opidx = h.operands[opr].usei
            opn = h.operands[opr].useopr
        op = CMDSimpler.heap[opidx].instr
        if h.operands[opr].idx != 0:
            lst = self.TraceListAddr(opidx, opn)

            if len(lst) == 0:
                return True

            lop = lst.pop()[1]
            if lop.mnemonic not in (UD_Imov, UD_Imovzx, UD_Imovsx) or \
               lop.operand[1].type != UD_OP_MEM or lop.operand[1].lval.lval != self.GetKeyOffset(h.operands[opr].tkey):
                return True

            h.operands[opr].tp = TH_OPR_IMM

            movcnt = 0
            if op.operand[opr].type == UD_OP_MEM:
                movcnt = 1

            while len(lst) > 0:
                lop = lst.pop()[1]
                if IsOpClass(lop.mnemonic, 0, 0, 1) and lop.operand[1].type == UD_OP_IMM:
                    h.operands[opr].decoders.append( TG_OP_DEC(lop.mnemonic, lop.operand[1].size, lop.operand[1].lval.lval) )
                elif lop.mnemonic == UD_Iadd and lop.operand[1].type == UD_OP_REG and lop.operand[1].base in (UD_R_EBP, UD_R_RBP):
                    h.operands[opr].tp = TH_OPR_REG
                elif lop.mnemonic in (UD_Imov, UD_Imovzx, UD_Imovsx) and lop.operand[1].type == UD_OP_MEM:
                    movcnt += 1

            if movcnt > 2:
                xlog("!", "if movcnt > 2:", hex(h.hndlID), movcnt)

            if movcnt == 2 and h.operands[opr].tp == TH_OPR_REG:
                h.operands[opr].tp = TH_OPR_MEM_REG
            elif movcnt == 1 and h.operands[opr].tp == TH_OPR_IMM:
                h.operands[opr].tp = TH_OPR_MEM_IMM
            elif movcnt == 1 and h.operands[opr].tp == TH_OPR_REG:
                pass
            elif movcnt == 0 and h.operands[opr].tp == TH_OPR_IMM:
                pass
            else:
                xlog("!", "movcnt", movcnt, "tp", h.operands[opr].tp, hex(h.hndlID))

        return True

    def DecryptTigerData(self, h):
        return self.DecryptTigerOperandDataMy2(h, 0) and self.DecryptTigerOperandDataMy2(h, 1)

    def RecoveryAdvancedHandler(self, h):
        if (self.CheckHndlTCall(h) or \
           self.CheckHndlTNop(h) or \
           self.CheckHndlTPush(h) or \
           self.CheckHndlTPop(h) or \
           self.CheckHndlTInc(h) or \
           self.CheckHndlTInc(h) or \
           self.CheckHndlTDec(h) or \
           self.CheckHndlTNot(h) or \
           self.CheckHndlTNeg(h) or \
           self.CheckHndlTAdd(h) or \
           self.CheckHndlTSub(h) or \
           self.CheckHndlTAnd(h) or \
           self.CheckHndlTXor(h) or \
           self.CheckHndlTOr(h) or \
           self.CheckHndlTShl(h) or \
           self.CheckHndlTShr(h) or \
           self.CheckHndlTRcl(h) or \
           self.CheckHndlTRcr(h) or \
           self.CheckHndlTRol(h) or \
           self.CheckHndlTRor(h) or \
           self.CheckHndlTCmp(h) or
           self.CheckHndlTTest(h) or \
           self.CheckHndlTImul(h) or \
           self.CheckHndlTMovsx(h) or \
           self.CheckHndlTMovzx(h) or \
           self.CheckHndlTMov(h) or \
           self.CheckHndlUnshuffle(h) or \
           self.CheckHndlAddImgBase(h)):
            return self.DecryptTigerData(h)
        return True

    def StepNop(self, h, reader):
        #self.stepParams[0] = OP_NOP

        rk = ud()
        rk.mnemonic = UD_Inop
        self.traced.Add(rk, reader.addr)

        if h.idxList:
            return self.StepFlow(h, reader.Read2(h.flowReadOffset), False)
        return self.StepFlow(h, reader.Read2(h.flowReadOffset), True)

    def StepPop(self, h, reader):
        self.StepOpcodeRegions(h, reader)

        self.step_params[0] = "POP"

        rk = ud()
        rk.mnemonic = UD_Ipop

        val = self.StepOperand(h, 0, rk.operand[0])

        self.step_params[1] = val

        if len(self.trStkReg) > 0:
            irlreg = self.trStkReg[0]
            self.trStkReg = self.trStkReg[1:]

            if True:
                #irlreg != 4:
                self.vmReg[val] = irlreg
                self.realRegs.add(val)

            self.StepOperand(h, 0, rk.operand[0])

        if self.traceLog:
            xlog(self.TxtWop(rk))

        self.traced.Add(rk, reader.addr)

        return self.StepFlow(h, reader.Read2(h.flowReadOffset), False)

    def StepUniBin(self, h, reader, TXTMNEM, MNEM, dbg = False):
        self.StepOpcodeRegions(h, reader, dbg)

        rk = ud()
        rk.mnemonic = MNEM

        val1 = self.StepOperand(h, 0, rk.operand[0])
        val2 = self.StepOperand(h, 1, rk.operand[1])

        self.step_params[0] = TXTMNEM
        self.step_params[1] = val1
        self.step_params[2] = val2

        if self.traceLog:
            xlog(self.TxtWop(rk))

        self.traced.Add(rk, reader.addr)

        return self.StepFlow(h, reader.Read2(h.flowReadOffset), False, dbg)

    def StepUnary(self, h, reader, TXTMNEM, MNEM, dbg = False):
        self.StepOpcodeRegions(h, reader, dbg)

        rk = ud()
        rk.mnemonic = MNEM

        val = self.StepOperand(h, 0, rk.operand[0])

        self.step_params[0] = TXTMNEM
        self.step_params[1] = val

        if self.traceLog:
            xlog(self.TxtWop(rk))

        self.traced.Add(rk, reader.addr)

        return self.StepFlow(h, reader.Read2(h.flowReadOffset), False, dbg)

    def StepUnshuffle(self, h, reader):
        r1 = reader.Read2(h.opcodeOffsets[0])
        r2 = reader.Read2(h.opcodeOffsets[1])
        r3 = reader.Read2(h.opcodeOffsets[2])
        r4 = reader.Read2(h.opcodeOffsets[3])
        r5 = reader.Read2(h.opcodeOffsets[4])
        r6 = reader.Read2(h.opcodeOffsets[5])
        rv1 = self.GetVMReg(r1)
        rv2 = self.GetVMReg(r2)
        rv3 = self.GetVMReg(r3)
        rv4 = self.GetVMReg(r4)
        rv5 = self.GetVMReg(r5)
        rv6 = self.GetVMReg(r6)
        p1 = reader.Read2(h.opcodeOffsets[6])
        p2 = reader.Read2(h.opcodeOffsets[7])
        p3 = reader.Read2(h.opcodeOffsets[8])
        p4 = reader.Read2(h.opcodeOffsets[9])
        p5 = reader.Read2(h.opcodeOffsets[10])
        p6 = reader.Read2(h.opcodeOffsets[11])
        self.vmReg[p1] = rv6
        self.vmReg[p2] = rv5
        self.vmReg[p3] = rv4
        self.vmReg[p4] = rv3
        self.vmReg[p5] = rv2
        self.vmReg[p6] = rv1

        # seems
        # 7 6 2 1 3 0
        #xlog(rv6, rv5, rv4, rv3, rv2, rv1)

        #self.realRegs.clear()
        self.realRegs.add(p1)
        self.realRegs.add(p2)
        self.realRegs.add(p3)
        self.realRegs.add(p4)
        self.realRegs.add(p5)
        self.realRegs.add(p6)

        self.step_params[0] = "UNSHUFFLE"
        #xlog("--------------------------------------------------------")

        rk = ud()
        rk.mnemonic = THOP_UNSHUFFLE
        self.traced.Add(rk, reader.addr)
        return self.StepFlow(h, reader.Read2(h.flowReadOffset), False)

    def StepCall(self, h, reader):
        synt = "ERR "
        self.step_params[0] = "ERR"

        rk = ud()
        rk.addr = h.hndlID

        if h.operands[1].tp != 0: # CALL
            self.step_params[0] = "CALL"
            rk.mnemonic = UD_Icall
        elif h.operands[0].tp != 0:
            self.step_params[0] = "JMP"
            rk.mnemonic = UD_Ijmp
        else:
            xlog("CALL ERR")
            return False

        val = 0
        if h.operands[0].sz == 8:
            val = reader.Read1(h.opcodeOffsets[0])
        elif h.operands[0].sz == 16:
            val = reader.Read2(h.opcodeOffsets[0])
        elif h.operands[0].sz == 32:
            val = reader.Read4(h.opcodeOffsets[0])
        elif h.operands[0].sz == 64:
            val = reader.Read8(h.opcodeOffsets[0])

        rk.operand[0].size = h.operands[0].sz
        if h.operands[0].tp == TH_OPR_REG:
            rk.operand[0].type = UD_OP_REG
            rk.operand[0].size = self.bits
            rk.operand[0].base = self.ConvRegSize(val, self.bits)
        elif h.operands[0].tp == TH_OPR_IMM:
            rk.operand[0].type = UD_OP_IMM
            rk.operand[0].size = 32
            if h.operands[0].flags != 0:
                val = UDWORD(val + self.imageBase)
            rk.operand[0].lval.lval = val
        elif h.operands[0].tp == TH_OPR_MEM_IMM:
            rk.operand[0].type = UD_OP_MEM
            rk.operand[0].size = self.bits
            if h.operands[0].flags != 0:
                val = UDWORD(val + self.imageBase)
            rk.operand[0].lval.lval = val
        elif h.operands[0].tp == TH_OPR_MEM_REG:
            rk.operand[0].type = UD_OP_MEM
            rk.operand[0].size = self.bits
            rk.operand[0].base = self.ConvRegSize(val, self.bits)

        if h.operands[1].tp != 0:
            val = 0
            if h.operands[1].sz == 8:
                val = reader.Read1(h.opcodeOffsets[1])
            elif h.operands[1].sz == 16:
                val = reader.Read2(h.opcodeOffsets[1])
            elif h.operands[1].sz == 32:
                val = reader.Read4(h.opcodeOffsets[1])
            elif h.operands[1].sz == 64:
                val = reader.Read8(h.opcodeOffsets[1])

            retaddr = 0
            if h.operands[1].tp == TH_OPR_REG:
                synt = "\t\tRET-> {}".format(udFamilyReg(self.GetVMReg(val), self.bits))
            elif h.operands[1].tp == TH_OPR_IMM:
                if h.operands[1].flags != 0:
                    val = UDWORD(val + self.imageBase)
                synt = "\t\tRET-> {:x}".format(val)
                retaddr = val
            elif h.operands[1].tp == TH_OPR_MEM_IMM:
                if h.operands[1].flags != 0:
                    val = UDWORD(val + self.imageBase)
                synt = "\t\tRET-> [{:x}]".format(val)
                m = self.GetMM(val)
                if m != None:
                    retaddr = GetDWORD(val)
            elif h.operands[1].tp == TH_OPR_MEM_REG:
                synt = "\t\tRET-> [{}]".format(udFamilyReg(self.GetVMReg(val), self.bits))

            if retaddr != 0:
                rk.operand[1].type = UD_OP_IMM
                rk.operand[1].size = 32
                rk.operand[1].value = retaddr
                isvm, of, hid =  self.CheckEnterVM(retaddr)
                if isvm:
                    l = LABELS.GetLabel(UDWORD(of + self.imageBase), hid)
                    l.specialData = (self.vmReg.copy(), self.realRegs.copy(), self.vmEspReg)
                    rk.operand[1].lval.lval = UDWORD(of + self.imageBase)
                    #xlog("Add RET {:x} {:x}".format(UINT(of + self.imageBase), hid))

        if self.traceLog:
            xlog(self.TxtWop(rk) + synt)

        self.traced.Add(rk, self.trAddr)
        return True

    def StepImgBase(self, h, reader):
        self.StepOpcodeRegions(h, reader)

        rk = ud()
        rk.mnemonic = UD_Iadd

        val1 = self.StepOperand(h, 0, rk.operand[0])
        rk.operand[1].type = UD_OP_IMM
        rk.operand[1].size = 32
        rk.operand[1].lval.lval = self.imageBase

        self.step_params[0] = "ADD"
        self.step_params[1] = val1
        self.step_params[2] = self.imageBase

        if self.traceLog:
            xlog(self.TxtWop(rk))

        self.traced.Add(rk, reader.addr)

        return self.StepFlow(h, reader.Read2(h.flowReadOffset), False)

    def StepAdvanced(self, h, reader):

        if h.tp == TH_NOP:
            return self.StepNop(h, reader)
        elif h.tp == TH_POP:
            # HACK
            if self.traced.count >= 2 and \
              ((self.traced.heap[self.traced.count - 1].instr.mnemonic == WOP_RESET and \
               self.traced.heap[self.traced.count - 2].instr.mnemonic == WOP_SSTACK) or \
               (self.traced.heap[self.traced.count - 2].instr.mnemonic == WOP_RESET and \
                self.traced.heap[self.traced.count - 1].instr.mnemonic == WOP_SSTACK)) and \
               len(self.trStkReg) == 0:
                self.ResetInputStack()
                xlog("HACK! Restore POP REGS")
            return self.StepPop(h, reader)
        elif h.tp == TH_PUSH:
            return self.StepUnary(h, reader, "PUSH", UD_Ipush)
        elif h.tp == TH_TEST:
            return self.StepUniBin(h, reader, "TEST", UD_Itest)
        elif h.tp == TH_CMP:
            return self.StepUniBin(h, reader, "CMP", UD_Icmp, dbg=True)
        elif h.tp == TH_SUB:
            return self.StepUniBin(h, reader, "SUB", UD_Isub, dbg=True)
        elif h.tp == TH_ADD:
            return self.StepUniBin(h, reader, "ADD", UD_Iadd)
        elif h.tp == TH_AND:
            return self.StepUniBin(h, reader, "AND", UD_Iand)
        elif h.tp == TH_OR:
            return self.StepUniBin(h, reader, "OR", UD_Ior)
        elif h.tp == TH_XOR:
            return self.StepUniBin(h, reader, "XOR", UD_Ixor)
        elif h.tp == TH_SHL:
            return self.StepUniBin(h, reader, "SHL", UD_Ishl)
        elif h.tp == TH_SHR:
            return self.StepUniBin(h, reader, "SHR", UD_Ishr)
        elif h.tp == TH_MOV:
            return self.StepUniBin(h, reader, "MOV", UD_Imov)
        elif h.tp == TH_MOVSX:
            return self.StepUniBin(h, reader, "MOVSX", UD_Imovsx)
        elif h.tp == TH_MOVZX:
            return self.StepUniBin(h, reader, "MOVZX", UD_Imovzx)
        elif h.tp == TH_INC:
            return self.StepUnary(h, reader, "INC", UD_Iinc)
        elif h.tp == TH_DEC:
            return self.StepUnary(h, reader, "DEC", UD_Idec)
        elif h.tp == TH_NOT:
            return self.StepUnary(h, reader, "NOT", UD_Inot)
        elif h.tp == TH_NEG:
            return self.StepUnary(h, reader, "NEG", UD_Ineg)
        elif h.tp == TH_SHL:
            return self.StepUniBin(h, reader, "SHL", UD_Ishl)
        elif h.tp == TH_SHR:
            return self.StepUniBin(h, reader, "SHR", UD_Ishr)
        elif h.tp == TH_RCL:
            return self.StepUniBin(h, reader, "RCL", UD_Ircl)
        elif h.tp == TH_RCR:
            return self.StepUniBin(h, reader, "RCR", UD_Ircr)
        elif h.tp == TH_ROL:
            return self.StepUniBin(h, reader, "ROL", UD_Irol)
        elif h.tp == TH_ROR:
            return self.StepUniBin(h, reader, "ROR", UD_Iror)
        elif h.tp == TH_UNSHUFLE:
            return self.StepUnshuffle(h, reader)
        elif h.tp == WH_CALL:
            return self.StepCall(h, reader)
        elif h.tp == TH_IMGBASE:
            return self.StepImgBase(h, reader)
        elif h.tp == -1:
            self.StepOpcodeRegions(h, reader)
            return self.StepFlow(h, reader.Read2(h.flowReadOffset), False)
        return False

    def StepOperand(self, h, opid, outop):
        opi = h.operands[opid]
        val = self.GetKeyData(opi.tkey)

        for d in opi.decoders:
            _, val = ComputeVal(d.mnem, d.sz, val, d.data)

        if opi.tp == TH_OPR_IMM:
            if opi.sz == 8:
                val &= 0xFF
            elif opi.sz == 16:
                val &= 0xFFFF
            elif opi.sz == 32:
                val &= 0xFFFFFFFF

        outop.size = opi.sz
        if opi.tp == TH_OPR_REG:
            outop.type = UD_OP_REG
            outop.base = self.ConvRegSize(val, self.bits)
        elif opi.tp == TH_OPR_IMM:
            outop.type = UD_OP_IMM
            outop.lval.lval = val
        elif opi.tp == TH_OPR_MEM_REG:
            outop.type = UD_OP_MEM
            outop.base = self.ConvRegSize(val, self.bits)
        elif opi.tp == TH_OPR_MEM_IMM:
            outop.type = UD_OP_MEM
            outop.lval.lval = val

        return val

    def TxtWildOperator(self, op):
        if op.mnemonic in TIGER_OPTXT:
            return TIGER_OPTXT[op.mnemonic]
        return WILD.TxtWildOperator(self, op)


    def SimplifyDoubleUnshuffle(self, trace):
        i = 0
        while trace.Bounds(i, 1):
            if trace.heap[i].instr.mnemonic == THOP_UNSHUFFLE and \
               trace.heap[i + 1].instr.mnemonic == THOP_UNSHUFFLE:
                trace.heap[i + 1].instr.mnemonic = UD_Inone
            i += 1
        trace.Cleaner()

    def SimplifyPushCallJmp(self, trace):
        i = 0
        while i < trace.count:
            if trace.Bounds(i, 11) and \
               trace.heap[i].instr.mnemonic == UD_Ipush and \
               trace.heap[i + 1].instr.mnemonic == UD_Ipush and \
               trace.heap[i + 2].instr.mnemonic in (UD_Ipushfw, UD_Ipushfd, UD_Ipushfq) and \
               trace.heap[i + 3].instr.mnemonic == UD_Ipush and \
               trace.heap[i + 4].instr.mnemonic == UD_Ipush and \
               trace.heap[i + 5].instr.mnemonic == UD_Ipush and \
               trace.heap[i + 6].instr.mnemonic == UD_Ipush and \
               trace.heap[i + 7].instr.mnemonic == UD_Ipush and \
               trace.heap[i + 8].instr.mnemonic == UD_Ipush and \
               trace.heap[i + 9].instr.mnemonic == UD_Ipush and \
               trace.heap[i + 10].instr.mnemonic == THOP_UNSHUFFLE:
                if trace.heap[i + 11].instr.mnemonic == UD_Icall:
                    for j in range(11):
                        trace.heap[i + j].instr.mnemonic = UD_Inone
                elif trace.Bounds(i, 12) and \
                     trace.heap[i + 11].instr.mnemonic == UD_Inop and \
                     trace.heap[i + 12].instr.mnemonic == UD_Icall:
                    for j in range(12):
                        trace.heap[i + j].instr.mnemonic = UD_Inone
            if trace.Bounds(i, 10) and \
                trace.heap[i].instr.mnemonic == UD_Ipush and \
                trace.heap[i + 1].instr.mnemonic in (UD_Ipushfw, UD_Ipushfd, UD_Ipushfq) and \
                trace.heap[i + 2].instr.mnemonic == UD_Ipush and \
                trace.heap[i + 3].instr.mnemonic == UD_Ipush and \
                trace.heap[i + 4].instr.mnemonic == UD_Ipush and \
                trace.heap[i + 5].instr.mnemonic == UD_Ipush and \
                trace.heap[i + 6].instr.mnemonic == UD_Ipush and \
                trace.heap[i + 7].instr.mnemonic == UD_Ipush and \
                trace.heap[i + 8].instr.mnemonic == UD_Ipush and \
                trace.heap[i + 9].instr.mnemonic == THOP_UNSHUFFLE:
                if trace.heap[i + 10].instr.mnemonic in (UD_Ijmp, WOP_UNDEF) or \
                   trace.heap[i + 10].instr.mnemonic in JCC_LIST:
                    for j in range(10):
                        trace.heap[i + j].instr.mnemonic = UD_Inone
                elif trace.Bounds(i, 11) and \
                     trace.heap[i + 10].instr.mnemonic == UD_Inop and \
                    (trace.heap[i + 11].instr.mnemonic in (UD_Ijmp, WOP_UNDEF) or \
                     trace.heap[i + 11].instr.mnemonic in JCC_LIST):
                    for j in range(11):
                        trace.heap[i + j].instr.mnemonic = UD_Inone
            i += 1
        trace.Cleaner()

    def SimplifyResetPop(self, trace):
        i = 0
        while i < trace.count:
            if trace.Bounds(i, 11) and \
                trace.heap[i].instr.mnemonic == WOP_SSTACK and \
                trace.heap[i + 1].instr.mnemonic == WOP_RESET and \
                trace.heap[i + 2].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 3].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 4].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 5].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 6].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 7].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 8].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 9].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 10].instr.mnemonic in (UD_Ipopfw, UD_Ipopfd, UD_Ipopfq) and \
                trace.heap[i + 11].instr.mnemonic == WOP_RSTACK:
                for j in range(12):
                    trace.heap[i + j].instr.mnemonic = UD_Inone
            elif trace.Bounds(i, 11) and \
                trace.heap[i].instr.mnemonic == WOP_RESET and \
                trace.heap[i + 1].instr.mnemonic == WOP_SSTACK and \
                trace.heap[i + 2].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 3].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 4].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 5].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 6].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 7].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 8].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 9].instr.mnemonic == UD_Ipop and \
                trace.heap[i + 10].instr.mnemonic in (UD_Ipopfw, UD_Ipopfd, UD_Ipopfq) and \
                trace.heap[i + 11].instr.mnemonic == WOP_RSTACK:
                for j in range(12):
                    trace.heap[i + j].instr.mnemonic = UD_Inone
            i += 1
        trace.Cleaner()

    def SimplifyModifyStack(self, trace):
        i = 0
        while i < trace.count:
            if trace.Bounds(i, 1) and \
                trace.heap[i].instr.mnemonic in (UD_Iadd, UD_Isub) and \
                trace.heap[i + 1].instr.mnemonic == WOP_LSTACK and \
                trace.heap[i].instr.operand[0].type == UD_OP_REG and \
                trace.heap[i].instr.operand[0].lval.lval == 0x1043:

                trace.heap[i + 1].instr.mnemonic = UD_Inone
                trace.heap[i].instr.operand[0].base = udFamilyReg(UD_R_FAMILY_SP, self.bits)

            i += 1
        trace.Cleaner()


    def SimplifyComplexUniversal(self, trace):
        i = 0
        while i < trace.count:
            if trace.Bounds(i, 4):
                op0 = trace.heap[i].instr
                op1 = trace.heap[i + 1].instr
                op2 = trace.heap[i + 2].instr
                op3 = trace.heap[i + 3].instr
                op4 = trace.heap[i + 4].instr

                if op0.mnemonic == UD_Imov and \
                   op1.mnemonic == UD_Ishl and \
                   op2.mnemonic == UD_Iadd and \
                   op3.mnemonic == UD_Iadd and \
                   op0.operand[0].type == UD_OP_REG and \
                   op1.operand[0].type == UD_OP_REG and \
                   op2.operand[0].type == UD_OP_REG and \
                   op3.operand[0].type == UD_OP_REG and \
                   op0.operand[0].base & 0x2000 and \
                   op1.operand[0].base == op0.operand[0].base and \
                   op2.operand[0].base == op0.operand[0].base and \
                   op3.operand[0].base == op0.operand[0].base and \
                   op0.operand[1].type == UD_OP_REG and \
                   op1.operand[1].type == UD_OP_IMM and \
                   op2.operand[1].type == UD_OP_REG and \
                   op3.operand[1].type == UD_OP_IMM:
                    if op4.operand[0].type == UD_OP_MEM and op4.operand[0].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.mnemonic = UD_Inone
                        op4.operand[0].base = op2.operand[1].base
                        op4.operand[0].index = op0.operand[1].base
                        op4.operand[0].scale = (1 << op1.operand[1].lval.lval)
                        op4.operand[0].lval.lval = op3.operand[1].lval.lval
                    elif op4.operand[1].type == UD_OP_MEM and op4.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.mnemonic = UD_Inone
                        op4.operand[1].base = op2.operand[1].base
                        op4.operand[1].index = op0.operand[1].base
                        op4.operand[1].scale = (1 << op1.operand[1].lval.lval)
                        op4.operand[1].lval.lval = op3.operand[1].lval.lval
                    elif op4.mnemonic == UD_Imov and \
                         op4.operand[0].type == UD_OP_REG and \
                         op4.operand[1].type == UD_OP_REG and \
                         op4.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.mnemonic = UD_Inone
                        op4.mnemonic = UD_Ilea
                        op4.operand[1].type = UD_OP_MEM
                        op4.operand[1].size = self.bits
                        op4.operand[1].base = op2.operand[1].base
                        op4.operand[1].index = op0.operand[1].base
                        op4.operand[1].scale = (1 << op1.operand[1].lval.lval)
                        op4.operand[1].lval.lval = op3.operand[1].lval.lval

            if trace.Bounds(i, 3):
                op0 = trace.heap[i].instr
                op1 = trace.heap[i + 1].instr
                op2 = trace.heap[i + 2].instr
                op3 = trace.heap[i + 3].instr

                if op0.mnemonic == UD_Imov and \
                   op1.mnemonic == UD_Ishl and \
                   op2.mnemonic == UD_Iadd and \
                   op0.operand[0].type == UD_OP_REG and \
                   op1.operand[0].type == UD_OP_REG and \
                   op2.operand[0].type == UD_OP_REG and \
                   op0.operand[0].base & 0x2000 and \
                   op1.operand[0].base == op0.operand[0].base and \
                   op2.operand[0].base == op0.operand[0].base and \
                   op0.operand[1].type == UD_OP_REG and \
                   op1.operand[1].type == UD_OP_IMM and \
                   op2.operand[1].type == UD_OP_REG:
                    if op3.operand[0].type == UD_OP_MEM and op3.operand[0].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.operand[0].base = op2.operand[1].base
                        op3.operand[0].index = op0.operand[1].base
                        op3.operand[0].scale = (1 << op1.operand[1].lval.lval)
                        op3.operand[0].lval.lval = 0
                    elif op3.operand[1].type == UD_OP_MEM and op3.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.operand[1].base = op2.operand[1].base
                        op3.operand[1].index = op0.operand[1].base
                        op3.operand[1].scale = (1 << op1.operand[1].lval.lval)
                        op3.operand[1].lval.lval = 0
                    elif op3.mnemonic == UD_Imov and \
                         op3.operand[0].type == ID_REG and \
                         op3.operand[1].type == ID_REG and \
                         op3.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.mnemonic = UD_Ilea
                        op3.operand[1].type = UD_OP_MEM
                        op3.operand[1].size = self.bits
                        op3.operand[1].base = op2.operand[1].base
                        op3.operand[1].index = op0.operand[1].base
                        op3.operand[1].scale = (1 << op1.operand[1].lval.lval)
                        op3.operand[1].lval.lval = 0

                if op0.mnemonic == UD_Imov and \
                   op1.mnemonic == UD_Ishl and \
                   op2.mnemonic == UD_Iadd and \
                   op0.operand[0].type == UD_OP_REG and \
                   op1.operand[0].type == UD_OP_REG and \
                   op2.operand[0].type == UD_OP_REG and \
                   op0.operand[0].base & 0x2000 and \
                   op1.operand[0].base == op0.operand[0].base and \
                   op2.operand[0].base == op0.operand[0].base and \
                   op0.operand[1].type == UD_OP_REG and \
                   op1.operand[1].type == UD_OP_IMM and \
                   op2.operand[1].type == UD_OP_IMM:
                    if op3.operand[0].type == UD_OP_MEM and op3.operand[0].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.operand[0].base = UD_NONE
                        op3.operand[0].index = op0.operand[1].base
                        op3.operand[0].scale = (1 << op1.operand[1].lval.lval)
                        op3.operand[0].lval.lval = op2.operand[1].lval.lval
                    elif op3.operand[1].type == UD_OP_MEM and op3.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.operand[1].base = UD_NONE
                        op3.operand[1].index = op0.operand[1].base
                        op3.operand[1].scale = (1 << op1.operand[1].lval.lval)
                        op3.operand[1].lval.lval = op2.operand[1].lval.lval
                    elif op3.mnemonic == UD_Imov and \
                         op3.operand[0].type == UD_OP_REG and \
                         op3.operand[1].type == UD_OP_REG and \
                         op3.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.mnemonic = UD_Ilea
                        op3.operand[1].size = self.bits
                        op3.operand[1].type = UD_OP_MEM
                        op3.operand[1].base = UD_NONE
                        op3.operand[1].index = op0.operand[1].base
                        op3.operand[1].scale = (1 << op1.operand[1].lval.lval)
                        op3.operand[1].lval.lval = op2.operand[1].lval.lval

                if op0.mnemonic == UD_Imov and \
                   op1.mnemonic == UD_Iadd and \
                   op2.mnemonic == UD_Iadd and \
                   op0.operand[0].type == UD_OP_REG and \
                   op1.operand[0].type == UD_OP_REG and \
                   op2.operand[0].type == UD_OP_REG and \
                   op0.operand[0].base & 0x2000 and \
                   op1.operand[0].base == op0.operand[0].base and \
                   op2.operand[0].base == op0.operand[0].base and \
                   op0.operand[1].type == UD_OP_REG and \
                   op1.operand[1].type == UD_OP_REG and \
                   op2.operand[1].type == UD_OP_IMM:
                    if op3.operand[0].type == UD_OP_MEM and op3.operand[0].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.operand[0].base = op0.operand[1].base
                        op3.operand[0].index = op1.operand[1].base
                        op3.operand[0].scale = 0
                        op3.operand[0].lval.lval = op2.operand[1].lval.lval
                    elif op3.operand[1].type == UD_OP_MEM and op3.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.operand[1].base = op0.operand[1].base
                        op3.operand[1].index = op1.operand[1].base
                        op3.operand[1].scale = 0
                        op3.operand[1].lval.lval = op2.operand[1].lval.lval
                    elif op3.mnemonic == UD_Imov and \
                         op3.operand[0].type == UD_OP_REG and \
                         op3.operand[1].type == UD_OP_REG and \
                         op3.operand[1].value == op0.operand[0].value:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Inone
                        op3.mnemonic = UD_Ilea
                        op3.operand[1].type = UD_OP_MEM
                        op3.operand[1].size = self.bits
                        op3.operand[1].base = op0.operand[1].base
                        op3.operand[1].index = op1.operand[1].base
                        op3.operand[1].scale = 0
                        op3.operand[1].lval.lval = op2.operand[1].lval.lval

            if trace.Bounds(i, 2):
                op0 = trace.heap[i].instr
                op1 = trace.heap[i + 1].instr
                op2 = trace.heap[i + 2].instr

                if op0.mnemonic == UD_Imov and \
                   op1.mnemonic == UD_Iadd and \
                   op0.operand[0].type == UD_OP_REG and \
                   op1.operand[0].type == UD_OP_REG and \
                   op0.operand[0].base & 0x2000 and \
                   op1.operand[0].base == op0.operand[0].base and \
                   op0.operand[1].type == UD_OP_REG and \
                   op1.operand[1].type == UD_OP_IMM:
                    if op2.operand[0].type == UD_OP_MEM and op2.operand[0].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.operand[0].base = op0.operand[1].base
                        op2.operand[0].index = UD_NONE
                        op2.operand[0].scale = 0
                        op2.operand[0].lval.lval = op1.operand[1].lval.lval
                    elif op2.operand[1].type == UD_OP_MEM and op2.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.operand[1].base = op0.operand[1].base
                        op2.operand[1].index = UD_NONE
                        op2.operand[1].scale = 0
                        op2.operand[1].lval.lval = op1.operand[1].lval.lval
                    elif op2.mnemonic == UD_Imov and \
                         op2.operand[0].type == UD_OP_REG and \
                         op2.operand[1].type == UD_OP_REG and \
                         op2.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Ilea
                        op2.operand[1].type = UD_OP_MEM
                        op2.operand[1].size = self.bits
                        op2.operand[1].base = op0.operand[1].base
                        op2.operand[1].index = UD_NONE
                        op2.operand[1].scale = 0
                        op2.operand[1].lval.lval = op1.operand[1].lval.lval

                if op0.mnemonic == UD_Imov and \
                   op1.mnemonic == UD_Iadd and \
                   op0.operand[0].type == UD_OP_REG and \
                   op1.operand[0].type == UD_OP_REG and \
                   op0.operand[0].base & 0x2000 and \
                   op1.operand[0].base == op0.operand[0].base and \
                   op0.operand[1].type == UD_OP_REG and \
                   op1.operand[1].type == UD_OP_REG:
                    if op2.operand[0].type == UD_OP_MEM and op2.operand[0].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.operand[0].base = op0.operand[1].base
                        op2.operand[0].index = op1.operand[1].base
                        op2.operand[0].scale = 0
                        op2.operand[0].lval.lval = 0
                    elif op2.operand[1].type == UD_OP_MEM and op2.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.operand[1].base = op0.operand[1].base
                        op2.operand[1].index = op1.operand[1].base
                        op2.operand[1].scale = 0
                        op2.operand[1].lval.lval = 0
                    elif op2.mnemonic == UD_Imov and \
                         op2.operand[0].type == UD_OP_REG and \
                         op2.operand[1].type == UD_OP_REG and \
                         op2.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Inone
                        op2.mnemonic = UD_Ilea
                        op2.operand[1].type = UD_OP_MEM
                        op2.operand[1].size = self.bits
                        op2.operand[1].base = op0.operand[1].base
                        op2.operand[1].index = op1.operand[1].base
                        op2.operand[1].scale = 0
                        op2.operand[1].lval.lval = 0

            if trace.Bounds(i, 1):
                op0 = trace.heap[i].instr
                op1 = trace.heap[i + 1].instr

                if op0.mnemonic == UD_Imov and \
                   op0.operand[0].type == UD_OP_REG and \
                   op0.operand[0].base & 0x2000 and \
                   op0.operand[1].type in (UD_OP_REG, UD_OP_IMM):
                    if op1.operand[0].type == UD_OP_MEM and op1.operand[0].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.operand[0].base = UD_NONE
                        op1.operand[0].index = UD_NONE
                        op1.operand[0].scale = 0
                        op1.operand[0].lval.lval = 0
                        if op0.operand[1].type == UD_OP_REG:
                            op1.operand[0].base = op0.operand[1].base
                        else:
                            op1.operand[0].lval.lval = op0.operand[1].lval.lval
                    elif op1.operand[1].type == UD_OP_MEM and op1.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.operand[1].base = UD_NONE
                        op1.operand[1].index = UD_NONE
                        op1.operand[1].scale = 0
                        op1.operand[1].lval.lval = 0
                        if op0.operand[1].type == UD_OP_REG:
                            op1.operand[1].base = op0.operand[1].base
                        else:
                            op1.operand[1].lval.lval = op0.operand[1].lval.lval

                    elif op1.mnemonic in (UD_Icall, UD_Ijmp, UD_Ipush) and \
                        op1.operand[0].type == UD_OP_REG and \
                        op1.operand[0].base == op0.operand[0].base:

                        op0.mnemonic = UD_Inone
                        op1.operand[0] = op0.operand[1].Copy()
                    elif op1.mnemonic == UD_Imov and \
                         op1.operand[0].type == UD_OP_REG and \
                         op1.operand[1].type == UD_OP_REG and \
                         op1.operand[1].base == op0.operand[0].base:
                        op0.mnemonic = UD_Inone
                        op1.mnemonic = UD_Ilea
                        op1.operand[1].type = UD_OP_MEM
                        op1.operand[1].size = self.bits
                        op1.operand[1].base = UD_NONE
                        op1.operand[1].index = UD_NONE
                        op1.operand[1].scale = 0
                        op1.operand[1].lval.lval = 0
                        if op0.operand[1].type == UD_OP_REG:
                            op1.operand[1].base = op0.operand[1].base
                        else:
                            op1.operand[1].lval.lval = op0.operand[1].lval.lval

            i += 1
        trace.Cleaner()

    def SimplifyComplexAddress(self, trace):
        i = 0
        while i < trace.count:
            if not trace.Bounds(i, 1):
                break

            op0 = trace.heap[i].instr
            op1 = trace.heap[i + 1].instr

            if op0.mnemonic in (UD_Imov, UD_Iadd) and \
               op1.mnemonic == UD_Iadd and \
               op0.operand[0].type == UD_OP_REG and \
               op0.operand[0].base & 0x2000 and \
               op0.operand[1].type == UD_OP_IMM and \
               op1.operand[0].type == UD_OP_REG and \
               op1.operand[1].type == UD_OP_IMM and \
               op1.operand[0].base == op0.operand[0].base:

                op1.mnemonic = UD_Inone
                op0.operand[1].lval.lval = UDWORD(op0.operand[1].lval.lval + op1.operand[1].lval.lval)

            i += 1
        trace.Cleaner()

    def DeleteSpecial(self, trace):
        i = 0
        while i < trace.count:
            op = trace.heap[i].instr
            if op.mnemonic in (WOP_RESET, THOP_UNSHUFFLE, WOP_LSTACK):
                op.mnemonic = UD_Inone
            elif op.mnemonic == UD_Imov and \
                op.operand[0].type == UD_OP_REG and \
                op.operand[1].type == UD_OP_REG and \
                op.operand[0].base == op.operand[1].base:
                op.mnemonic = UD_Inone
            i += 1
        trace.Cleaner()

    def Simplify(self, trace):
        counter = 0
        while True:
            cnt = trace.count
            self.SimplifyDoubleUnshuffle(trace)
            self.SimplifyPushCallJmp(trace)
            self.SimplifyResetPop(trace)
            self.SimplifyModifyStack(trace)
            self.SimplifyComplexAddress(trace)
            self.SimplifyComplexUniversal(trace)

            self.DeleteSpecial(trace)

            if cnt == trace.count:
                counter += 1
                if counter >= 2:
                    break
            else:
                counter = 0