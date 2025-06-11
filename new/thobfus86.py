import udis86
from udis86_decode import *
from udis86_itabh import *
from udis86_syn import udTranslateIntel
from udis86_types import *
from udis86_util import *
from xrkutil import *
import inspect
import binascii

JCC_LIST = (UD_Ija, UD_Ijae, UD_Ijb, UD_Ijbe, UD_Ijz, UD_Ijnz,
	        UD_Ijg, UD_Ijge, UD_Ijl, UD_Ijle, UD_Ijo, UD_Ijno,
	        UD_Ijp, UD_Ijnp, UD_Ijs, UD_Ijns, UD_Ijcxz, UD_Ijecxz, UD_Ijrcxz)

class InsEntry:
	instr = udis86.ud()
	addr = 0
	unk1 = 0
	keyData = 0
	index = 0
	
	def __init__(self, ins = udis86.ud() , ad = 0, un1 = 0, kd = 0, idx = 0):
		self.instr = ins
		self.addr = ad
		self.unk1 = un1
		self.keyData = kd
		self.index = idx

	def Copy(self):
		t = InsEntry()
		t.addr = self.addr
		t.unk1 = self.unk1
		t.keyData = self.keyData
		t.index = self.index
		t.instr = self.instr.Copy()
		return t


def FUN_10065850(op1, op2):
	t = UB(op2) >> 4
	if (op1 & 0xF) < (op2 & 0xF):
		return False
	else:
		if (op2 & 0xF) == 1 and t > 3:
			t = t - 4
		if (UB(op1) >> 4) == t:
			return True
	return False

def SameBaseAndBigger(op1, op2):
	if op1.size < op2.size:
		return False
	elif op2.size == 8 and op2.base in (UD_R_AH, UD_R_CH, UD_R_DH, UD_R_BH) and\
		 op1.base == op2.base - (UD_R_AH - UD_R_AL):
		return True
	elif op1.base == op2.base:
		return True
	return False


MOVCLASS = (UD_Imov,)
IDNNCLASS = (UD_Iinc, UD_Idec, UD_Ineg, UD_Inot)
ASXORCLASS = (UD_Iadd, UD_Isub, UD_Ixor, UD_Ior, UD_Iand, UD_Ishl, UD_Ishr)


def IsOpClass(opid, mv, idnn, asx):
	if isinstance(opid, udis86.ud):
		opid = opid.mnemonic
	if mv and opid == UD_Imov:
		return True
	elif idnn and opid in (UD_Iinc, UD_Idec, UD_Ineg, UD_Inot):
		return True
	elif asx and opid in (UD_Iadd, UD_Isub, UD_Ixor, UD_Ior, UD_Iand, UD_Ishl, UD_Ishr):
		return True
	return False

def FUN_10060650(u):
	if (u.mnemonic == UD_Iadd or u.mnemonic == UD_Isub) and u.operand[1].type == UD_OP_IMM and\
	   (u.operand[1].lval.udword == 0xffffffff or u.operand[1].lval.udword == 1):
		return True
	return False

ComputeValDbg = False

def ComputeVal(op, sz, val1, val2, dbg=False):
	if sz == 8:
		v1 = UB(val1)
		v2 = UB(val2)
	elif sz == 16:
		v1 = UWORD(val1)
		v2 = UWORD(val2)
	elif sz == 32:
		v1 = UDWORD(val1)
		v2 = UDWORD(val2)
	elif sz == 64:
		v1 = UQDWORD(val1)
		v2 = UQDWORD(val2)
	else:
		xlog("ComputeVal incorrect size {:d}".format(sz))
		return False, val1

	if ComputeValDbg or dbg:
		xlog("op {}   {:x} {:x}".format(udis86.udLookupMnemonic(op), v1, v2))
		
	if op == UD_Iadd:
		v1 = v1 + v2
	elif op == UD_Iand:
		v1 = v1 & v2
	elif op == UD_Idec:
		v1 = v1 - 1
	elif op == UD_Iinc:
		v1 = v1 + 1
	elif op == UD_Ineg:
		v1 = -v1
	elif op == UD_Inot:
		v1 = ~v1
	elif op == UD_Ior:
		v1 = v1 | v2
	elif op == UD_Ishl:
		v1 = v1 << (v2 & 0x1f)
	elif op == UD_Ishr:
		v1 = v1 >> (v2 & 0x1f)
	elif op == UD_Isub:
		v1 = v1 - v2
	elif op == UD_Ixor:
		v1 = v1 ^ v2
	else:
		return False, val1
	
	if sz == 8:
		return True, (val1 & 0xFFFFFFFFFFFFFF00) | UB(v1)
	elif sz == 16:
		return True, (val1 & 0xFFFFFFFFFFFF0000) | UWORD(v1)
	elif sz == 32:
		return True, (val1 & 0xFFFFFFFF00000000) | UDWORD(v1)
	elif sz == 64:
		return True , UQDWORD(v1)


class InsList:
	unk = 0
	maxlen = 0x10000
	heap = None
	count = 0
	errAddr = -1
	errAddr2 = -1
	log = None
	SPREG = UD_R_ESP

	def __init__(self):
		self.log = list()
		self.heap = list()

	def Clone(self):
		c = InsList()
		c.maxlen = self.count + 64
		c.heap = [None] * c.maxlen
		c.count = self.count
		for i in range(self.count, c.maxlen):
			c.heap[i] = InsEntry()

		for i in range(self.count):
			c.heap[i] = self.heap[i].Copy()

		c.unk = self.unk
		return c

	def Last(self):
		return self.heap[ self.count - 1 ]

	def FindIndexByIndex(self, idx):
		for i in range(self.count):
			if self.heap[i].index == idx:
				return i
		return -1
	
	def GetOP(self, a):
		for i in range(self.count):
			if self.heap[i].addr == a:
				ins = self.heap[i].instr
				return ins.Copy()
		return None

	def GetOpPos(self, a):
		for i in range(self.count):
			if self.heap[i].addr == a:
				return i
		return -1
	
	def Clear(self):
		self.heap = [None] * self.maxlen
		for i in range(self.maxlen):
			self.heap[i] = InsEntry()
		self.unk = 0
		self.count = 0
	
	def Add(self, instr, addr):
		if self.count >= self.maxlen:
			return False

		self.heap[self.count] = InsEntry(instr , addr)
		self.count += 1
		return True
	
	def Cleaner(self, i = 0, cnt = -1):
		while cnt != 0:
			if i >= self.count:
				break
			if self.heap[i].instr.mnemonic == UD_Inone:
				self.heap[i:self.maxlen-1] = self.heap[i+1:self.maxlen]
				#for j in range(i, self.maxlen - 1):
				#	self.heap[j] = self.heap[j + 1]
				self.heap[self.maxlen - 1] = InsEntry()
				i -= 1
				self.count -= 1
			cnt -= 1
			i += 1

	def GetFirstAfterAddr(self, addr):
		for i in range(self.count):
			if self.heap[i].addr >= addr:
				return self.heap[i]
		return None

	def AddrToIndex(self, addr):
		for i in range(self.count):
			if self.heap[i].addr == addr:
				return i
		return -1


	def CheckCommonArithmetic(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i + 1].instr

		if op0.mnemonic == UD_Imov and op1.mnemonic != UD_Imov and\
		   op0.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
		   op0.operand[1].type == UD_OP_IMM and\
		   op1.operand[0].isSame( op0.operand[0] ):

			j = 0
			while j < self.count - i:
				ojp = self.heap[i + 1 + j].instr
				if IsOpClass(ojp.mnemonic, 0, 1, 1) and\
				   ojp.operand[0].isSame( op0.operand[0] ) and\
				   ojp.operand[1].type in (UD_NONE, UD_OP_IMM):
					j += 1
				else:
					break

			if j > 0:
				if self.unk == 1 and self.count <= i + 1 + j:
					return True #brake

				self.DebugErrModify(i, j + 1, 0)

				val = op0.operand[1].lval.lval
				for k in range(j):
					okp = self.heap[i + 1 + k].instr
					if op0.operand[0].type == UD_OP_REG:
						_,val = ComputeVal(okp.mnemonic, op0.operand[0].size, val, okp.operand[1].lval.lval)
					okp.mnemonic = 0

				op0.operand[1].lval.lval = val

				self.Cleaner(i, 10 + k)
				return True #brake
		return False

	def CheckRiscArithmetic(self, i):
		return False

	def CollapseArithmetic(self, vmtp):
		i = self.count - 1
		while i >= 0:
			if vmtp in (3, 4):
				if self.CheckRiscArithmetic(i):
					break
			else:
				if self.CheckCommonArithmetic(i):
					break
			i -= 1

	def DebugErrModify(self, i, num, part):
		fun = inspect.stack()[1][3]
		j = 0

		self.log.append("{:08x} - {:08x}  {} {}".format(self.heap[i].addr, self.heap[i + j - 1].addr, fun, part))

		if self.errAddr < 0 and self.errAddr2 < 0:
			return

		adr1 = 0
		adr2 = 0

		if self.errAddr > 0:
			adr1 = self.errAddr
			adr2 = adr1 + 1

		if self.errAddr2 > 0:
			adr2 = self.errAddr2
			if adr2 < adr1:
				adr2 = adr1 + 1

		while j < num:
			cmd = self.heap[i + j]
			if cmd.addr >= adr1 and cmd.addr < adr2:
				xlog("Modify of 0x{:X} by {}  {:d}".format(self.errAddr, fun, part))
				j = 0

				while j < num:
					u = self.heap[i+j].instr
					xlog("\t addr {:x}    {}".format(self.heap[i + j].addr, udTranslateIntel(u)))

					#xlog(' '.join('{:02x}'.format(x) for x in self.heap[i + j].instr.bts))

					j += 1

				break
			j += 1
	
	def CheckRound1_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if op0.mnemonic == UD_Isub and op1.mnemonic == UD_Imov and\
		   op0.operand[0].type == UD_OP_REG and \
		   op0.operand[0].base in (UD_R_ESP , UD_R_RSP) and \
		   op0.operand[1].type == UD_OP_IMM and \
		   op0.operand[1].lval.udword in (2, 4, 8) and \
		   op1.operand[0].type == UD_OP_MEM and \
		   op1.operand[0].size in (16, 32, 64) and \
		   op1.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and \
		   op1.operand[1].type == UD_OP_REG :
		   
			#xlog("CheckRound1_1")
		   
			if op1.operand[1].base in (UD_R_SP, UD_R_ESP, UD_R_RSP):
				if op2.mnemonic == UD_Iadd and\
				   op2.operand[0].type == UD_OP_MEM and op2.operand[1].type == UD_OP_IMM and\
				   op2.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and \
				   op2.operand[1].lval.udword in (2, 4, 8):
					op0.mnemonic = UD_Ipush
					op0.CopyPrefixes(op1)
					op0.operand[0] = op1.operand[1].Copy()
					op0.operand[1] = ud_operand()
					op1.mnemonic = UD_Inone
					op2.mnemonic = UD_Inone
					self.DebugErrModify(i, 3, 0)
					self.Cleaner(i, 10)
			else:
				op0.mnemonic = UD_Ipush
				op0.CopyPrefixes(op1)
				op0.operand[0] = op1.operand[1].Copy()
				op0.operand[1] = ud_operand()

				op1.mnemonic = UD_Inone
				self.DebugErrModify(i, 2, 1)
				self.Cleaner(i, 10)
	
	def CheckRound1_2(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if (op0.mnemonic == UD_Ipush and op1.mnemonic == UD_Imov) and\
		   op0.operand[0].type == UD_OP_REG and\
		   op1.operand[0].type == UD_OP_MEM and \
		   op1.operand[0].size in (16, 32, 64) and \
		   op1.operand[1].type == UD_OP_REG and \
		   op1.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)):
		   
			#xlog("CheckRound1_2")
		   
			if op1.operand[1].base in (UD_R_SP, UD_R_ESP, UD_R_RSP):
				if op2.mnemonic == UD_Iadd and\
					op2.operand[0].type == UD_OP_MEM and op2.operand[1].type == UD_OP_IMM and\
					op2.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and\
					op2.operand[1].lval.udword in (2, 4, 8):

					op0.mnemonic = UD_Ipush
					op0.CopyPrefixes(op1)
					op0.operand[0] = op1.operand[1].Copy()
					op1.mnemonic = UD_Inone
					op2.mnemonic = UD_Inone
					self.DebugErrModify(i, 3, 0)
					self.Cleaner(i, 10)
			else:
				op0.mnemonic = UD_Ipush
				op0.CopyPrefixes(op1)
				op0.operand[0] = op1.operand[1].Copy()
				op1.mnemonic = UD_Inone
				self.DebugErrModify(i, 2, 1)
				self.Cleaner(i, 10)
				
	def CheckRound1_3(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr

		# push imm
		# mov (q/d)word ptr [(r/e)sp], reg
		if op0.mnemonic == UD_Ipush and op1.mnemonic == UD_Imov and\
		   op0.operand[0].type == UD_OP_IMM and\
		   op1.operand[0].type == UD_OP_MEM and\
		   op1.operand[0].size in (16, 32, 64) and\
		   op1.operand[1].type == UD_OP_REG and\
		   op1.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)):
		   
			#xlog("CheckRound1_3")

			# mov (q/d)word ptr [(r/e)sp], (r/e)sp
			if op1.operand[1].base in (UD_R_SP, UD_R_ESP, UD_R_RSP):
				if op2.mnemonic == UD_Iadd and\
					op2.operand[0].type == UD_OP_MEM and op2.operand[1].type == UD_OP_IMM and\
					op2.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and\
					op2.operand[1].lval.udword in (2, 4, 8):
					#push *sp
					op0.mnemonic = UD_Ipush
					op0.operand[0] = op1.operand[1].Copy()
					op1.mnemonic = UD_Inone
					op2.mnemonic = UD_Inone
					self.DebugErrModify(i, 3, 0)
					self.Cleaner(i, 10)
			else:
				#push reg
				op0.mnemonic = UD_Ipush
				op0.operand[0] = op1.operand[1].Copy()
				op1.mnemonic = UD_Inone
				self.DebugErrModify(i, 2, 1)
				self.Cleaner(i, 10)
	
	def CheckRound2_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr

		# mov reg, (q/d)word ptr[(r/e)sp]
		# add reg, imm
		if op0.mnemonic == UD_Imov and op1.mnemonic == UD_Iadd and\
		   op0.operand[0].type == UD_OP_REG and \
		   op0.operand[0].base not in (UD_R_SP, UD_R_ESP, UD_R_RSP) and\
		   op0.operand[1].type == UD_OP_MEM and\
		   op0.operand[1].size in (16, 32, 64) and\
		   op0.operand[1].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and\
		   op1.operand[0].type == UD_OP_REG and\
		   op1.operand[1].type == UD_OP_IMM and\
		   op1.operand[0].base in (UD_R_ESP, UD_R_RSP) and\
		   op1.operand[1].lval.udword in (2, 4, 8):
			#xlog("CheckRound2_1 1")
			op0.mnemonic = UD_Ipop
			op0.operand[1] = ud_operand()
			op1.mnemonic = UD_Inone
			self.DebugErrModify(i, 2, 0)
			self.Cleaner(i, 10)
		   
		if op0.mnemonic == UD_Imov and\
		   op0.operand[0].type == UD_OP_REG and \
		   op0.operand[0].base in (UD_R_SP, UD_R_ESP, UD_R_RSP) and \
		   op0.operand[1].type == UD_OP_MEM and \
		   op0.operand[1].size in (16, 32, 64) and \
		   op0.operand[1].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)):
			#xlog("CheckRound2_1 2")
			op0.mnemonic = UD_Ipop
			op0.operand[1] = ud_operand()
			self.DebugErrModify(i, 1, 1)
			self.Cleaner(i, 10)
	
	def CheckRound3_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		op4 = self.heap[i+4].instr
		op5 = self.heap[i+5].instr
		
		if op0.mnemonic == UD_Ipush and \
		   op0.operand[0].type == UD_OP_REG and \
		   op0.operand[0].base not in (UD_R_ESP, UD_R_RSP) and \
			\
		   op1.mnemonic == UD_Imov and \
		   op1.operand[0].type == UD_OP_REG and \
		   op1.operand[0].base == op0.operand[0].base and \
		   op1.operand[1].type == UD_OP_REG and \
		   op1.operand[1].base in (UD_R_ESP, UD_R_RSP) and \
 			\
		   op2.mnemonic == UD_Iadd and \
		   op2.operand[0].type == UD_OP_REG and \
		   op2.operand[0].base == op0.operand[0].base and \
		   op2.operand[1].type == UD_OP_IMM and \
		   op2.operand[1].lval.udword in (4, 8) and \
			\
		   op3.mnemonic in (UD_Iadd, UD_Isub) and \
		   op3.operand[0].type == UD_OP_REG and \
		   op3.operand[0].base == op0.operand[0].base and \
		   op3.operand[1].type == UD_OP_IMM and \
			\
		   op4.mnemonic == UD_Ixchg and \
		  ((op4.operand[0].TSZ() in ((UD_OP_MEM, 32), (UD_OP_MEM, 64)) and\
		    op4.operand[1].type == UD_OP_REG) or \
		   (op4.operand[1].TSZ() in ((UD_OP_MEM, 32), (UD_OP_MEM, 64)) and \
			op4.operand[0].type == UD_OP_REG)) and \
		  ((op4.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and\
			op4.operand[1].base == op0.operand[0].base) or \
		   (op4.operand[1].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and\
		   op4.operand[0].base == op0.operand[0].base)) and \
			\
		   op5.mnemonic == UD_Ipop and\
		   op5.operand[0].type == UD_OP_REG and \
		   op5.operand[0].base in (UD_R_ESP, UD_R_RSP):
		   
			#xlog("CheckRound3_1")
			op0.mnemonic = op3.mnemonic
			op0.operand[0].type = UD_OP_REG
			op0.operand[0].base = op5.operand[0].base # ESP or RSP
			op0.operand[1].type = UD_OP_IMM
			op0.operand[1].size = 32
			op0.operand[1].lval.udword = op3.operand[1].lval.udword
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			op3.mnemonic = UD_Inone
			op4.mnemonic = UD_Inone
			op5.mnemonic = UD_Inone
			self.DebugErrModify(i, 6, 0)
			self.Cleaner(i, 10)
	
	def CheckRound4_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if op0.mnemonic == UD_Ixor and\
		   op1.mnemonic == UD_Ixor and\
		   op2.mnemonic == UD_Ixor and\
	   		op0.operand[0].isSame( op1.operand[1] ) and \
			op0.operand[1].isSame( op1.operand[0] ) and \
		    op1.operand[1].isSame( op2.operand[0] ) and \
			op1.operand[0].isSame( op2.operand[1] ):
			#xlog("CheckXorXorXor1")
			op0.mnemonic = UD_Ixchg
			op0.operand[0] = op1.operand[0].Copy()
			op0.operand[1] = op2.operand[0].Copy()
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			self.DebugErrModify(i, 3, 0)
			self.Cleaner(i, 10)

	def CheckRound4_2(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic == UD_Imov and\
		   op2.mnemonic == UD_Ipop and\
		   op0.operand[0].type == UD_OP_REG and\
		   op1.operand[0].type == UD_OP_REG and\
		   op1.operand[1].type == UD_OP_MEM and\
		   op1.operand[1].size in (32, 64) and\
		   op2.operand[0].type == UD_OP_MEM and \
		   op2.operand[0].size in (32, 64) and \
		   op0.operand[0].base not in (UD_R_ESP, UD_R_RSP) and\
		   op0.operand[0].base == op1.operand[0].base and\
		   op1.operand[1].BIS() in ((UD_R_ESP, 0, 0), (UD_R_RSP, 0, 0)) and\
		   op1.operand[1].lval.udword in (4, 8) and\
		   op2.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)):
		   
			#xlog("CheckPushMovPop1")
			op0.mnemonic = UD_Ixchg
			op0.operand[1] = op2.operand[0].Copy()
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			self.DebugErrModify(i, 3, 0)
			self.Cleaner(i, 10)
	
	def CheckRound4_3(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		op4 = self.heap[i+4].instr
		
		if op0.mnemonic == UD_Ipush and \
		   op1.mnemonic == UD_Imov and \
		   op2.mnemonic == UD_Imov and \
		   op3.mnemonic == UD_Imov and \
		   op4.mnemonic == UD_Ipop and \
		   op0.operand[0].type == UD_OP_REG and \
		   op1.operand[0].type == UD_OP_REG and \
		   op3.operand[1].type == UD_OP_REG and \
		   op4.operand[0].type == UD_OP_REG and \
		   SameBaseAndBigger(op0.operand[0], op1.operand[0]) and\
		   op1.operand[0].isSame( op3.operand[1] ) and\
		   op1.operand[1].isSame( op2.operand[0] ) and\
		   op2.operand[1].isSame( op3.operand[0] ) and\
		   op4.operand[0].base == op0.operand[0].base:
			
			#xlog("CheckPushMovMovMovPop1")
			op0.mnemonic = UD_Ixchg
			op0.CopyPrefixes( op3 )
			op0.operand[0] = op3.operand[0].Copy()
			op0.operand[1] = op2.operand[0].Copy()

			if op0.operand[0].type == UD_OP_MEM and\
				op0.operand[0].base in (UD_R_ESP, UD_R_RSP):

				if op4.operand[0].size == 64:
					op0.operand[0].lval.udword -= 8
				elif op4.operand[0].size == 32:
					op0.operand[0].lval.udword -= 4
				else:
					op0.operand[0].lval.udword -= 2

			if op0.operand[1].type == UD_OP_MEM and\
				op0.operand[1].base in (UD_R_ESP, UD_R_RSP):

				if op4.operand[0].size == 64:
					op0.operand[1].lval.udword += 8
				elif op4.operand[0].size == 32:
					op0.operand[1].lval.udword += 4
				else:
					op0.operand[1].lval.udword += 2

			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			op3.mnemonic = UD_Inone
			op4.mnemonic = UD_Inone
			self.DebugErrModify(i, 5, 0)
			self.Cleaner(i, 10)
	
	def CheckRound5_3(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		op4 = self.heap[i+4].instr

		#0: push reg
		#1: mov reg,imm
		#2: mov x2,imm
		#3: ___ x2,reg
		#4: pop reg
		
		if op0.mnemonic == UD_Ipush and \
		   op1.mnemonic == UD_Imov and \
		   op2.mnemonic == UD_Imov and\
		   op3.mnemonic in (MOVCLASS + ASXORCLASS) and\
		   op4.mnemonic == UD_Ipop and \
		   op0.operand[0].type == UD_OP_REG and\
		   op1.operand[0].type == UD_OP_REG and\
		   op1.operand[1].type == UD_OP_IMM and\
		   op2.operand[1].type == UD_OP_IMM and\
		   op3.operand[1].type == UD_OP_REG and\
		   op4.operand[0].type == UD_OP_REG and\
		   SameBaseAndBigger(op0.operand[0], op1.operand[0]) and\
		   op2.operand[0].isSame( op3.operand[0] ) and\
		   op3.operand[1].isSame( op1.operand[0] ) and\
		   op4.operand[0].base == op0.operand[0].base:

	   		newval = 0
			if op3.operand[0].type == UD_OP_REG:
				s,newval = ComputeVal(op3.mnemonic, op3.operand[0].size, op2.operand[1].lval.uqword, op1.operand[1].lval.uqword)
			elif op3.operand[0].type == UD_OP_MEM:
				if op3.operand[0].base in (UD_R_ESP, UD_R_RSP):
					if op4.operand[0].size == 64:
						op3.operand[0].lval.udword -= 8
					elif op4.operand[0].size == 32:
						op3.operand[0].lval.udword -= 4
					else:
						op3.operand[0].lval.udword -= 2

				s,newval = ComputeVal(op3.mnemonic, op3.operand[0].size, op2.operand[1].lval.uqword, op1.operand[1].lval.uqword)
			
			#xlog("CheckPushMovMovXX1")
			
			op0.mnemonic = UD_Imov
			op0.CopyPrefixes(op3)
			op0.operand[0] = op3.operand[0].Copy()
			op0.operand[1] = op1.operand[1].Copy()
			op0.operand[1].lval.uqword = newval
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			op3.mnemonic = UD_Inone
			op4.mnemonic = UD_Inone
			self.DebugErrModify(i, 5, 0)
			self.Cleaner(i, 10)
	
	def CheckRound5_4(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		op4 = self.heap[i+4].instr
		op5 = self.heap[i+5].instr

		#0: push reg
		#1: mov reg,imm
		#2: mov x,imm
		#3: ___ x,reg
		#4: ___ x,imm
		#5: pop reg

		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic == UD_Imov and\
		   op2.mnemonic == UD_Imov and\
		   op3.mnemonic in (MOVCLASS + ASXORCLASS) and\
		   op4.mnemonic in (MOVCLASS + ASXORCLASS) and\
		   op5.mnemonic == UD_Ipop and\
		   op0.operand[0].type == UD_OP_REG and\
		   op1.operand[0].type == UD_OP_REG and\
		   op1.operand[1].type == UD_OP_IMM and\
		   op2.operand[0].type == UD_OP_REG and\
		   op2.operand[1].type == UD_OP_IMM and\
		  op3.operand[0].type == UD_OP_REG and op3.operand[1].type == UD_OP_REG and\
		  op4.operand[0].type == UD_OP_REG and op4.operand[1].type in (UD_OP_IMM, UD_OP_CONST) and\
		  op5.operand[0].type == UD_OP_REG and\
		  SameBaseAndBigger(op0.operand[0], op1.operand[0]) and\
		  op2.operand[0].base == op3.operand[0].base and\
		  op3.operand[0].base != op1.operand[0].base and\
		  op3.operand[0].base == op4.operand[0].base and\
		  op3.operand[1].base == op1.operand[0].base and\
		  op5.operand[0].base == op0.operand[0].base:
			
			#xlog("CheckPushMovMovXXPop1")
					  
			local_14 = op2.operand[1].lval.lval
			_,local_14 = ComputeVal(op3.mnemonic, op3.operand[0].size, local_14, op1.operand[1].lval.lval)
			_,local_14 = ComputeVal(op4.mnemonic, op4.operand[0].size, local_14, op4.operand[1].lval.lval)
			
			op0.mnemonic = UD_Imov
			op0.CopyPrefixes(op3)
			op0.operand[0] = op3.operand[0].Copy()
			op0.operand[1] = op1.operand[1].Copy()
			op0.operand[1].lval.lval = local_14
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			op3.mnemonic = UD_Inone
			op4.mnemonic = UD_Inone
			op5.mnemonic = UD_Inone
			self.DebugErrModify(i, 6, 0)
			self.Cleaner(i, 10)
	
	
	def CheckRound5_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr

		#0: push x1
		#1: pop x2
		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic == UD_Ipop and \
		  ( (op0.operand[0].size == op1.operand[0].size and op0.operand[0].size in (16, 32, 64) and \
			 ((op0.operand[0].type == UD_OP_REG and op1.operand[0].type == UD_OP_MEM) or\
		     (op0.operand[0].type == UD_OP_MEM and op1.operand[0].type == UD_OP_REG)) ) or \
			(op0.operand[0].type == UD_OP_REG and op1.operand[0].type == UD_OP_REG) or \
			(op0.operand[0].type == UD_OP_IMM and op0.operand[0].size in (16, 32, 64) and op1.operand[0].type == UD_OP_REG) ):

			#xlog("CheckPushPop1")
			#0: mov x2,x1
			op0.mnemonic = UD_Imov
			op0.operand[1] = op0.operand[0].Copy()
			op0.operand[0] = op1.operand[0].Copy()
			op1.mnemonic = UD_Inone

			self.DebugErrModify(i, 2, 0)
			self.Cleaner(i, 10)
	
	def CheckRound5_2(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr

		#0: push x1
		#1: sub|add|xor unknown ptr [esp],imm
		#2: pop x2
		#3: add|sub|xor x2,imm
		
		if op0.mnemonic == UD_Ipush and\
		   op2.mnemonic == UD_Ipop and\
		     ( (op1.mnemonic == UD_Isub and op3.mnemonic == UD_Iadd) or\
               (op1.mnemonic == UD_Iadd and op3.mnemonic == UD_Isub) or\
			   (op1.mnemonic == UD_Ixor and op3.mnemonic == UD_Ixor) ) and\
		   (op0.operand[0].type == UD_OP_REG or op0.operand[0].type == UD_OP_MEM) and\
		   op1.operand[0].type == UD_OP_MEM and\
		   op1.operand[1].type == UD_OP_IMM and\
           (op2.operand[0].type == UD_OP_REG or op2.operand[0].type == UD_OP_MEM) and\
		   (op3.operand[0].type == UD_OP_REG or op3.operand[0].type == UD_OP_MEM) and \
		   op3.operand[1].type == UD_OP_IMM and\
		   op3.operand[0].isSame( op2.operand[0] ) and\
		   op1.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and\
		   op1.operand[1].lval.lval == op3.operand[1].lval.lval and\
		   op3.operand[0].isSame( op2.operand[0] ):
		   
			#xlog("CheckPushXPopX1")
			op0.mnemonic = UD_Imov
			op0.operand[1] = op0.operand[0].Copy()
			op0.operand[0] = op2.operand[0].Copy()
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			op3.mnemonic = UD_Inone
			self.DebugErrModify(i, 4, 0)
			self.Cleaner(i, 10)
	
	def CheckRound8_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if ((op0.mnemonic == UD_Iadd and op2.mnemonic == UD_Isub) or\
			(op0.mnemonic == UD_Isub and op2.mnemonic == UD_Iadd)) and\
		   op1.mnemonic in (UD_Iadd, UD_Isub) and\
		   op0.operand[1].type == UD_OP_IMM and\
		   op1.operand[1].type != UD_OP_IMM and\
		   op2.operand[1].type == UD_OP_IMM and\
		   op0.operand[0].isSame( op1.operand[0] ) and\
		   op1.operand[0].isSame( op2.operand[0] ):
			
			#xlog("CheckAddSubSub1")
			op0.mnemonic = op1.mnemonic
			op0.operand[1] = op1.operand[1].Copy()
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			self.DebugErrModify(i, 3, 0)
			self.Cleaner(i, 10)
		   
	
	def CheckRound6_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if op0.mnemonic == UD_Ixchg and \
		   op1.mnemonic in (IDNNCLASS + ASXORCLASS) and \
		   op2.mnemonic == UD_Ixchg and\
		 ((op0.operand[0].isSame( op2.operand[0] ) and\
		   op0.operand[1].isSame( op2.operand[1] ) ) or\
		  (op0.operand[0].isSame( op2.operand[1] ) and\
		   op0.operand[1].isSame( op2.operand[0] ) )):
			if op0.operand[0].isSame( op1.operand[0] ) and\
			   op1.operand[1].type in (UD_NONE, UD_OP_IMM, UD_OP_CONST):
				
				op0.mnemonic = op1.mnemonic
				op0.operand[0] = op0.operand[1].Copy()
				op0.operand[1] = op1.operand[1].Copy()
				op1.mnemonic = UD_Inone
				op2.mnemonic = UD_Inone
				self.DebugErrModify(i, 3, 0)
				self.Cleaner(i, 10)
			elif op0.operand[1].isSame( op1.operand[0] ) and\
			    op1.operand[1].type in (UD_NONE, UD_OP_IMM, UD_OP_CONST):
			   
				op0.mnemonic = op1.mnemonic
				op0.operand[0] = op0.operand[0].Copy()
				op0.operand[1] = op1.operand[1].Copy()
				op1.mnemonic = UD_Inone
				op2.mnemonic = UD_Inone
				self.DebugErrModify(i, 3, 0)
				self.Cleaner(i, 10)

	def CheckRound6_2(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		
		if op0.mnemonic == UD_Ixchg and \
			op1.mnemonic in (IDNNCLASS + ASXORCLASS) and \
			op2.mnemonic in (IDNNCLASS + ASXORCLASS) and \
		   op3.mnemonic == UD_Ixchg and\
         ((op0.operand[0].isSame( op3.operand[0] ) and\
		   op0.operand[1].isSame( op3.operand[1] )) or\
		  (op0.operand[0].isSame( op3.operand[1] ) and\
		   op0.operand[1].isSame( op3.operand[0] ) )):
			
			if op0.operand[0].isSame( op1.operand[0] ) and\
			   op1.operand[1].type in (UD_NONE, UD_OP_IMM, UD_OP_CONST) and\
			   op2.operand[0].isSame( op1.operand[0] ) and\
               op2.operand[1].type in (UD_NONE, UD_OP_IMM, UD_OP_CONST):
			   
				op0.mnemonic = op1.mnemonic
				op0.operand[0] = op0.operand[1].Copy()
				op0.operand[1] = op1.operand[1].Copy()
				
				op1.mnemonic = op2.mnemonic
				
				op1.operand[0] = op0.operand[0].Copy()
				op1.operand[1] = op2.operand[1].Copy()
			   
				op2.mnemonic = UD_Inone
				op3.mnemonic = UD_Inone
				self.DebugErrModify(i, 4, 0)
				self.Cleaner(i, 10)
			elif op0.operand[1].isSame( op1.operand[0] ) and\
				 op1.operand[1].type in (UD_NONE, UD_OP_IMM, UD_OP_CONST):
				 
				op0.mnemonic = op1.mnemonic
				op0.operand[0] = op0.operand[0].Copy()
				op0.operand[1] = op1.operand[1].Copy()
				
				op1.mnemonic = op2.mnemonic;
				
				op1.operand[0] = op0.operand[0].Copy()
				op1.operand[1] = op2.operand[1].Copy()
			   
				op2.mnemonic = UD_Inone
				op3.mnemonic = UD_Inone
				self.DebugErrModify(i, 4, 1)
				self.Cleaner(i, 10)

	def CheckRound6_3(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic == UD_Imov and\
		   op2.mnemonic == UD_Ipop:
			if op0.operand[0].type == UD_OP_REG and\
			   op1.operand[1].type == UD_OP_REG:
				if op0.operand[0].isSame( op1.operand[0] ) and\
				   op1.operand[1].isSame( op2.operand[0] ):
				   
					op0.mnemonic = UD_Ixchg
					op0.operand[1] = op1.operand[1].Copy()
					op1.mnemonic = UD_Inone
					op2.mnemonic = UD_Inone
					self.DebugErrModify(i, 3, 0)
					self.Cleaner(i, 10)
					
			elif op0.operand[0].type == UD_OP_MEM and op1.operand[1].type == UD_OP_REG:
				if op0.operand[0].TSZ() == op1.operand[0].TSZ() and\
				   op1.operand[1].isSame( op2.operand[0] ):

					t = 0
					if op0.operand[0].size == 16:
						t = 2
					elif op0.operand[0].size == 32:
						t = 4
					elif op0.operand[0].size == 64:
						t = 8

					if op0.operand[0].base in (UD_R_ESP, UD_R_RSP) and\
					   op0.operand[0].index == op1.operand[0].index and\
					   op0.operand[0].scale == op1.operand[0].scale and\
					   op0.operand[0].lval.udword == op1.operand[0].lval.udword + t:
					   
						op0.mnemonic = UD_Ixchg
						op0.operand[1] = op1.operand[1].Copy()
						op1.mnemonic = UD_Inone
						op2.mnemonic = UD_Inone
						self.DebugErrModify(i, 3, 1)
						self.Cleaner(i, 10)
						
					elif op0.operand[0].isSame( op1.operand[0] ):
						 
						op0.mnemonic = UD_Ixchg
						op0.operand[1] = op1.operand[1].Copy()
						op1.mnemonic = UD_Inone
						op2.mnemonic = UD_Inone
						self.DebugErrModify(i, 3, 2)
						self.Cleaner(i, 10)
						
						
			elif op0.operand[0].type == UD_OP_REG and op1.operand[1].type == UD_OP_MEM:
				if op0.operand[0].isSame( op1.operand[0] ) and\
				   op1.operand[1].TSZ() == op2.operand[0].TSZ():

					t = 0
					if op1.operand[1].size == 16:
						t = 2
					elif op1.operand[1].size == 32:
						t = 4
					elif op1.operand[1].size == 64:
						t = 8

					if op1.operand[1].base in (UD_R_ESP, UD_R_RSP) and \
					   op1.operand[1].index == op2.operand[0].index and \
					   op1.operand[1].scale == op2.operand[0].scale and \
					   op1.operand[1].lval.udword == op2.operand[0].lval.udword + t:

						op0.mnemonic = UD_Ixchg
						op0.operand[1] = op2.operand[0].Copy()
						op1.mnemonic = UD_Inone
						op2.mnemonic = UD_Inone
						self.DebugErrModify(i, 3, 4)
						self.Cleaner(i, 10)
					elif op1.operand[1].isSame( op2.operand[0] ):
						 
						op0.mnemonic = UD_Ixchg
						op0.operand[1] = op1.operand[1].Copy()
						op1.mnemonic = UD_Inone
						op2.mnemonic = UD_Inone
						self.DebugErrModify(i, 3, 5)
						self.Cleaner(i, 10)
	
	
	def CheckRound7_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		
		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic == UD_Imov and\
		   op2.mnemonic in (MOVCLASS + ASXORCLASS) and\
		   op3.mnemonic == UD_Ipop and\
		   op0.operand[0].type == UD_OP_REG and\
		   op1.operand[0].type == UD_OP_REG and\
		   op2.operand[1].type == UD_OP_REG and\
		   op3.operand[0].type == UD_OP_REG and\
		   SameBaseAndBigger(op0.operand[0], op1.operand[0]) and\
		   op2.operand[1].base == op1.operand[0].base and\
		   op3.operand[0].base == op0.operand[0].base:
			
			if op2.operand[0].type == UD_OP_MEM and\
			   op2.operand[0].base in (UD_R_ESP, UD_R_RSP):

				t = 0
				if op0.operand[0].size == 16:
					t = 2
				elif op0.operand[0].size == 32:
					t = 4
				elif op0.operand[0].size == 64:
					t = 8
				op2.operand[0].lval.udword -= t
			
			op0.mnemonic = op2.mnemonic
			op0.CopyPrefixes(op2)
			op0.operand[0] = op2.operand[0].Copy()
			op0.operand[1] = op1.operand[1].Copy()
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			op3.mnemonic = UD_Inone
			self.DebugErrModify(i, 4, 0)
			self.Cleaner(i, 10)
	
	def CheckRound7_2(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if op0.mnemonic == UD_Ipush and \
		   op0.operand[0].type in (UD_OP_REG, UD_OP_MEM) and \
			\
		   op1.mnemonic in (IDNNCLASS + ASXORCLASS) and \
		   op1.operand[0].type in (UD_OP_REG, UD_OP_MEM) and \
		   op1.operand[0].BIS() in ((UD_R_ESP, 0, 0), (UD_R_RSP, 0, 0)) and \
			\
		   op2.mnemonic == UD_Ipop and\
		   op2.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
		   op2.operand[0].isSame( op0.operand[0] ):
		
			if op0.operand[0].type == UD_OP_REG and \
			   op0.operand[0].isBaseFamily((UD_R_EAX, UD_R_ECX, UD_R_EDX, UD_R_EBX)) and \
			   op1.operand[0].TSZ() == (UD_OP_MEM, 8) and \
			   op1.operand[0].lval.udword == 1:
				
				op0.mnemonic = op1.mnemonic
				op0.operand[0].type = op2.operand[0].type
				op0.operand[0].size = 8
				op0.operand[0].base = op2.operand[0].getBaseHigh()

				op0.operand[1] = op1.operand[1].Copy()
				op1.mnemonic = UD_Inone
				op2.mnemonic = UD_Inone
				self.DebugErrModify(i, 3, 0)
				self.Cleaner(i, 10)
			elif op1.operand[0].lval.udword == 0:

				op0.mnemonic = op1.mnemonic
				op0.CopyPrefixes(op1)
				op0.operand[0].type = op2.operand[0].type
				op0.operand[0].size = op1.operand[0].size

				if op2.operand[0].type == UD_OP_REG:
					op0.operand[0].base = udResizeBase(op2.operand[0].base, op1.operand[0].size)
				
				op0.operand[1] = op1.operand[1].Copy()
				op1.mnemonic = UD_Inone
				op2.mnemonic = UD_Inone
				self.DebugErrModify(i, 3, 1)
				self.Cleaner(i, 10)
				
		   
	def CheckRound7_3(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		
		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic in (IDNNCLASS + ASXORCLASS) and \
		   op2.mnemonic in (IDNNCLASS + ASXORCLASS) and \
		   op3.mnemonic == UD_Ipop and\
		   op0.operand[0].type == UD_OP_REG and\
		   op1.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
		   op2.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
		   op3.operand[0].type == UD_OP_REG and\
		   op1.operand[0].BIS() in ((UD_R_ESP, 0, 0), (UD_R_RSP, 0, 0)) and\
		   op2.operand[0].BIS() in ((UD_R_ESP, 0, 0), (UD_R_RSP, 0, 0)) and\
		   op1.operand[0].isSame( op2.operand[0] ) and\
		   op3.operand[0].isSame( op0.operand[0] ):

			if op0.operand[0].type == UD_OP_REG and \
			   op0.operand[0].isBaseFamily(UD_R_EAX, UD_R_ECX, UD_R_EDX, UD_R_EBX) and \
			   op1.operand[0].TSZ() == (UD_OP_MEM, 8) and \
			   op1.operand[0].lval.udword == 1:

				op0.mnemonic = op1.mnemonic
				op0.operand[0].type = op3.operand[0].type
				op0.operand[0].size = 8
				op0.operand[0].base = op3.operand[0].getBaseHigh()

				op0.operand[1] = op1.operand[1].Copy()

				op1.mnemonic = op2.mnemonic
				op1.operand[0].type = op3.operand[0].type
				op1.operand[0].size = 8
				op1.operand[0].base = op3.operand[0].getBaseHigh()

				op1.operand[1] = op2.operand[1].Copy()
				op2.mnemonic = UD_Inone
				op3.mnemonic = UD_Inone
				self.DebugErrModify(i, 4, 0)
				self.Cleaner(i, 10)
			elif op1.operand[0].lval.udword == 0:
				op0.mnemonic = op1.mnemonic
				op0.CopyPrefixes(op1)
				op0.operand[0].type = op3.operand[0].type
				op0.operand[0].size = op1.operand[0].size
				if op3.operand[0].type == UD_OP_REG:
					op0.operand[0].lval.udword = 0
					op0.operand[0].scale = 0
					op0.operand[0].index = 0
					op0.operand[0].base = udResizeBase(op3.operand[0].base, op1.operand[0].size)

				op0.operand[1] = op1.operand[1].Copy()

				op1.mnemonic = op2.mnemonic
				op1.CopyPrefixes(op2)
				op1.operand[0].type = op3.operand[0].type
				op1.operand[0].size = op2.operand[0].size
				if op3.operand[0].type == UD_OP_REG:
					op1.operand[0].lval.udword = 0
					op1.operand[0].scale = 0
					op1.operand[0].index = 0
					op1.operand[0].base = udResizeBase(op3.operand[0].base, op2.operand[0].size)

				op1.operand[1] = op2.operand[1].Copy()
				op2.mnemonic = UD_Inone
				op3.mnemonic = UD_Inone
				self.DebugErrModify(i, 4, 1)
				self.Cleaner(i, 10)
	
	def CheckRound7_4(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		op4 = self.heap[i+4].instr
		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic == UD_Imov and \
		   (op2.mnemonic in (IDNNCLASS + ASXORCLASS) or FUN_10060650(op2)) and\
		   op3.mnemonic == UD_Imov and\
		   op4.mnemonic == UD_Ipop and\
		   op0.operand[0].type == UD_OP_REG and \
		   op1.operand[0].type == UD_OP_REG and\
		   op1.operand[1].type == UD_OP_REG and\
		   op2.operand[0].type == UD_OP_REG and\
		   op3.operand[0].type == UD_OP_REG and\
		   op3.operand[1].type == UD_OP_REG and\
		   op4.operand[0].type == UD_OP_REG and\
		   SameBaseAndBigger(op0.operand[0], op1.operand[0]) and\
		   op1.operand[0].base == op3.operand[1].base and\
		   op1.operand[1].base == op3.operand[0].base and\
		   op2.operand[0].base == op3.operand[1].base and\
		   op4.operand[0].base == op0.operand[0].base:
			op0.mnemonic = op2.mnemonic
			op0.CopyPrefixes(op2)
			op0.operand[0] = op3.operand[0].Copy()
			op0.operand[1] = op2.operand[1].Copy()
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			op3.mnemonic = UD_Inone
			op4.mnemonic = UD_Inone
			self.DebugErrModify(i, 5, 0)
			self.Cleaner(i, 10)
	
	def Round9_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic == UD_Imov and\
		   op0.operand[0].type == UD_OP_REG and\
		   op1.operand[0].type == UD_OP_REG and\
		   op1.operand[1].type in (UD_OP_REG, UD_OP_IMM):
			if (op1.operand[1].type != UD_OP_REG or op1.operand[0].base != op1.operand[1].base) and\
			   op0.operand[0].base == op1.operand[0].base:
				loc14 = 0
				loc18 = 0
				loc1c = 0
				if op1.operand[1].type == UD_OP_REG and op1.operand[0].base != op1.operand[1].base and\
				   op1.operand[0].base == op0.operand[0].base:
					loc18 = 1
					loc1c = op1.operand[1].base
				j = 0
				while j < self.count - i:
					ojp0 = self.heap[i + 2 + j].instr
					ojp1 = self.heap[i + 3 + j].instr
					if ojp0.mnemonic not in (MOVCLASS + IDNNCLASS + ASXORCLASS):
						loc14 = 1
						break

					#   !mov   reg1[, imm]
					if ojp0.mnemonic != UD_Imov and\
					   ojp0.operand[0].type == UD_OP_REG and\
					   ojp0.operand[1].type in (UD_NONE, UD_OP_IMM, UD_OP_CONST):
						if ojp0.operand[0].base != op1.operand[0].base:
							loc14 = 1
							break

					#   !mov    reg1, reg2
					elif ojp0.mnemonic != UD_Imov and \
						 ojp0.operand[0].type == UD_OP_REG and\
						 ojp0.operand[1].type == UD_OP_REG and\
						 ojp0.operand[0].base != ojp0.operand[1].base:

						if ojp0.operand[0].base != op1.operand[0].base:
							loc14 = 1
							break

						loc18 += 1
						loc1c = ojp0.operand[1].base

					else:
						#  ___  reg, ... ptr [mem]
						if ojp0.operand[0].type == UD_OP_REG and ojp0.operand[1].type == UD_OP_MEM:

							if ojp0.operand[0].base == op1.operand[0].base or\
							   ojp0.operand[1].BISO() != (op1.operand[0].base, 0, 0, 0) or\
							   ojp1.mnemonic != UD_Ipop or\
							   ojp1.operand[0].type != UD_OP_REG or \
							   ojp1.operand[0].base != ojp0.operand[1].base or\
							   ojp1.operand[0].base != op0.operand[0].base:
								loc14 = 1
						#  ___  ... ptr [mem], reg
						elif ojp0.operand[0].type == UD_OP_MEM and ojp0.operand[1].type == UD_OP_REG:
							if ojp0.operand[1].base == op1.operand[0].base or\
							   ojp0.operand[0].BISO() != (op1.operand[0].base, 0, 0, 0) or \
							   ojp1.mnemonic != UD_Ipop or \
							   ojp1.operand[0].type != UD_OP_REG or \
							   ojp1.operand[0].base != ojp0.operand[0].base or \
							   ojp1.operand[0].base != op0.operand[0].base:
								loc14 = 1
						elif ojp0.operand[0].type == UD_OP_MEM and ojp0.operand[1].type == UD_OP_IMM:
							if ojp0.operand[0].BISO() != (op1.operand[0].base, 0, 0, 0) or \
							   ojp1.mnemonic != UD_Ipop or \
							   ojp1.operand[0].type != UD_OP_REG or \
							   ojp1.operand[0].base != ojp0.operand[0].base or\
							   ojp1.operand[0].base != op0.operand[0].base:
								loc14 = 1
						else:
							loc14 = 1
							break
						break

					j += 1

				if loc14 == 0 and loc18 == 1:
					ojp0 = self.heap[i + 2 + j].instr
					ojp1 = self.heap[i + 3 + j].instr

					op0.mnemonic = ojp0.mnemonic
					op0.CopyPrefixes(ojp0)
					loc20 = 0
					k = 0
					while k < j + 1:
						okp0 = self.heap[i + 1 + k].instr
						if k == 0:
							if op1.operand[1].type == UD_OP_REG:
								op1.mnemonic = UD_Inone
							else:
								loc20 = op1.operand[1].lval.lval
								okp0.mnemonic = UD_Inone
						else:
							if okp0.operand[1].type != UD_OP_REG:
								_,loc20 = ComputeVal(okp0.mnemonic, op1.operand[0].size, loc20, okp0.operand[1].lval.lval)
							okp0.mnemonic = UD_Inone
						k += 1
					
					ojp0.mnemonic = UD_Inone
					ojp1.mnemonic = UD_Inone
					if ojp0.operand[1].type == UD_OP_MEM:
						op0.operand[0] = ojp0.operand[0].Copy()
						op0.operand[1] = ojp0.operand[1].Copy()
						op0.operand[1].base = loc1c
						op0.operand[1].index = 0
						op0.operand[1].scale = 0
						op0.operand[1].lval.udword = loc20
						op0.operand[1].offset = 32
						op0.operand[1].lval.lval = 0
					else:
						op0.operand[0] = ojp0.operand[0].Copy()
						op0.operand[1].base = loc1c
						op0.operand[1].index = 0
						op0.operand[1].scale = 0
						op0.operand[1].lval.udword = loc20
						op0.operand[1].lval.lval = 0
						op0.operand[1].offset = 32
						op0.operand[1] = ojp0.operand[1].Copy()
					self.DebugErrModify(i, j + 4, 0)
					self.Cleaner(i, 10 + j)

	def Round9_2(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		op4 = self.heap[i+4].instr
		op5 = self.heap[i+5].instr
		op6 = self.heap[i+6].instr

		if op0.mnemonic == UD_Ipush and \
		   op0.operand[0].type == UD_OP_REG and\
		   op1.mnemonic == UD_Imov and \
		   op1.operand[0].type == UD_OP_REG and \
		   op1.operand[1].type == UD_OP_REG and \
		   op1.operand[0].base != op1.operand[1].base and \
		   op0.operand[0].base == op1.operand[0].base and \
		   op2.mnemonic == UD_Ishl and \
		   op2.operand[0].type == UD_OP_REG and \
		   op2.operand[1].type in (UD_OP_IMM, UD_OP_CONST) and \
		   op1.operand[0].base == op2.operand[0].base and \
		   op3.mnemonic == UD_Iadd and \
		   op3.operand[0].type == UD_OP_REG and \
		   op3.operand[1].type == UD_OP_IMM and \
		   op2.operand[0].base == op3.operand[0].base and \
		   op4.mnemonic == UD_Iadd and \
		   op4.operand[0].type == UD_OP_REG and \
		   op4.operand[1].type == UD_OP_REG and \
		   op3.operand[0].base == op4.operand[0].base and \
		   op5.mnemonic in (MOVCLASS + ASXORCLASS) and \
		   (op5.operand[1].type == UD_OP_MEM or op5.operand[0].type == UD_OP_MEM) and \
		  ((op5.operand[1].BISO() == (op2.operand[0].base, 0, 0, 0)) or \
		   (op5.operand[0].BISO() == (op2.operand[0].base, 0, 0, 0))) and \
		   op6.mnemonic == UD_Ipop and\
		   op6.operand[0].type == UD_OP_REG and\
		   op6.operand[0].base == op0.operand[0].base:

			op0.CopyPrefixes(op5)
			op0.mnemonic = op5.mnemonic
			
			if op5.operand[1].type == UD_OP_MEM:
				if op5.operand[1].base in (UD_R_ESP, UD_R_RSP):
					t = op0.operand[0].size // 8
					#if op0.operand[0].size == 16:
					#	t = 2
					#elif op0.operand[0].size == 32:
					#	t = 4
					#elif op0.operand[0].size == 64:
					#	t = 8
					op5.operand[1].lval.udword -= t

				op0.operand[0] = op5.operand[0].Copy()
				op0.operand[1].type = op5.operand[1].type
				op0.operand[1].size = op5.operand[1].size
				op0.operand[1].lval.lval = 0
				op0.operand[1].base = op4.operand[1].base
				op0.operand[1].index = op1.operand[1].base
				op0.operand[1].scale = (1 << op2.operand[1].lval.ubyte)
				op0.operand[1].val2 = op3.operand[1].lval.udword
			else:
				if op5.operand[0].base in (UD_R_ESP, UD_R_RSP):
					t = op0.operand[0].size // 8
					#if (op0.operand[0].GetB(0) & 0xF) != 3:
					#	t = 2
					op5.operand[0].lval.udword -= t

				op0.operand[1] = op5.operand[1].Copy()
				op0.operand[0].type = op5.operand[0].type
				op0.operand[0].size = op5.operand[0].size
				op0.operand[0].lval.lval = 0
				op0.operand[0].base = op4.operand[1].base
				op0.operand[0].index = op1.operand[1].base
				op0.operand[0].scale = (1 << op2.operand[1].lval.ubyte)
				op0.operand[0].val2 = op3.operand[1].lval.udword
			
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			op3.mnemonic = UD_Inone
			op4.mnemonic = UD_Inone
			op5.mnemonic = UD_Inone
			op6.mnemonic = UD_Inone
			self.DebugErrModify(i, 7, 0)
			self.Cleaner(i, 10)	
	
	def CheckRound11_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		
		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic == UD_Imov and\
		   op0.operand[0].type == UD_OP_REG and\
		   op1.operand[0].type == UD_OP_REG and\
		   op1.operand[1].type == UD_OP_IMM and \
		   SameBaseAndBigger(op0.operand[0], op1.operand[0]):
			loc14 = 0
			j = 0
			while j < self.count - i:
				ojp0 = self.heap[i + 2 + j].instr
				ojp1 = self.heap[i + 3 + j].instr
				if not ojp0.mnemonic in (MOVCLASS + IDNNCLASS + ASXORCLASS):
					loc14 = 1
					break
				
				if ojp0.mnemonic != UD_Imov and \
				   ojp0.operand[0].type == UD_OP_REG and \
                   ojp0.operand[1].type in (UD_NONE, UD_OP_IMM, UD_OP_CONST):
					if ojp0.operand[0].base != op1.operand[0].base:
						loc14 = 1
						break
				else:
					if ojp0.operand[0].type == UD_OP_REG and\
					   ojp0.operand[1].type == UD_OP_REG:
						if ojp0.operand[0].base == op1.operand[0].base or\
						   not SameBaseAndBigger(ojp1.operand[0], ojp0.operand[1]) or\
						   ojp1.mnemonic != UD_Ipop or\
						   ojp1.operand[0].type != UD_OP_REG or\
						   ojp1.operand[0].base != op0.operand[0].base:
							loc14 = 1
					else:
						if ojp0.operand[0].type == UD_OP_MEM and\
						   ojp0.operand[1].type == UD_OP_REG:
							if not SameBaseAndBigger(ojp1.operand[0], ojp0.operand[1]) or\
							   ojp1.mnemonic != UD_Ipop or\
							   ojp1.operand[0].type != UD_OP_REG or\
							   ojp1.operand[0].base != op0.operand[0].base:
								loc14 = 1
						else:
							loc14 = 1
							break
					break

				j += 1
				
			if loc14 == 0:
				ojp0 = self.heap[i + 2 + j].instr
				ojp1 = self.heap[i + 3 + j].instr

				op0.mnemonic = ojp0.mnemonic
				op0.CopyPrefixes(ojp0)
				op0.operand[0] = ojp0.operand[0].Copy()

				op1.mnemonic = UD_Inone
				
				loc18 = op1.operand[1].lval.lval
				
				k = 0
				while k < j:
					okp = self.heap[i + 2 + k].instr
					_,loc18 = ComputeVal(okp.mnemonic, op1.operand[0].size, loc18, okp.operand[1].lval.lval);
					okp.mnemonic = UD_Inone
					k += 1
					
				ojp0.mnemonic = UD_Inone
				ojp1.mnemonic = UD_Inone
				op0.operand[1] = op1.operand[1].Copy()
				op0.operand[1].lval.lval = loc18
				if op0.operand[0].type == UD_OP_MEM and\
				   op0.operand[0].base in (UD_R_ESP, UD_R_RSP):
					op0.operand[0].lval.udword -= ojp1.operand[0].size // 8
					#if (ojp1.operand[0].value & 0xf) == 3:
					#	op0.operand[0].val2 -= 4
					#else:
					#	op0.operand[0].val2 -= 2

				self.DebugErrModify(i, j + 4, 0)
				self.Cleaner(i, 10 + j)

	def Round12_1(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		
		if op0.mnemonic == UD_Ipush and \
		   op0.operand[0].type == UD_OP_IMM and \
		   op0.operand[0].lval.udword == 0 and \
		   op1.mnemonic == UD_Isub and \
		   op1.operand[0].type == UD_OP_MEM and \
		   op1.operand[1].type == UD_OP_REG and \
		   op1.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and \
		   op1.operand[1].base not in (UD_R_ESP, UD_R_RSP) and \
		   op2.mnemonic == UD_Ipop and\
		   op2.operand[0].type == UD_OP_REG and \
		   op1.operand[1].base == op2.operand[0].base:

			op0.mnemonic = UD_Ineg
			op0.operand[0] = op1.operand[1].Copy()
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			self.DebugErrModify(i, 3, 0)
			self.Cleaner(i, 10)	
			
	def Round12_2(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		
		if op0.mnemonic == UD_Inot:
			if op1.mnemonic == UD_Iinc:
				if op0.operand[0].type in (UD_OP_MEM, UD_OP_REG) and\
				   op0.operand[0].isSame( op1.operand[0] ):
					op0.mnemonic = UD_Ineg
					op1.mnemonic = UD_Inone
					self.DebugErrModify(i, 2, 0)
					self.Cleaner(i, 10)
			elif op1.mnemonic == UD_Iadd:
				if op1.operand[1].type == UD_OP_IMM and op1.operand[1].lval.lval == 1 and\
				   op0.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
				   op0.operand[0].isSame( op1.operand[0] ):
					op0.mnemonic = UD_Ineg
					op1.mnemonic = UD_Inone
					self.DebugErrModify(i, 2, 1)
					self.Cleaner(i, 10)
				
			elif op1.mnemonic == UD_Isub and\
			     op1.operand[1].type == UD_OP_IMM and\
				op0.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
				 op0.operand[0].isSame( op1.operand[0] ) and\
			  ((op1.operand[1].size == 8 and op1.operand[1].lval.ubyte == 0xff) or\
			     op1.operand[1].lval.sdword == -1):
				op0.mnemonic = UD_Ineg
				op1.mnemonic = UD_Inone
				self.DebugErrModify(i, 2, 2)
				self.Cleaner(i, 10)	
			
	
	def Round12_3(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		
		if op1.mnemonic == UD_Inot:
			if op0.mnemonic == UD_Idec:
				if op1.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
				   op1.operand[0].isSame( op0.operand[0] ):
					op0.mnemonic = UD_Ineg
					op1.mnemonic = UD_Inone
					self.DebugErrModify(i, 2, 0)
					self.Cleaner(i, 10)
			elif op0.mnemonic == UD_Iadd:
				if op0.operand[1].type == UD_OP_IMM and\
				   op1.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
				   op0.operand[0].isSame( op1.operand[0] ) and\
			    ((op0.operand[1].size == 8 and op0.operand[1].lval.ubyte == 0xff) or\
			       op0.operand[1].sdword == -1):
					op0.mnemonic = UD_Ineg
					op0.operand[1] = ud_operand()
					op1.mnemonic = UD_Inone
					self.DebugErrModify(i, 2, 1)
					self.Cleaner(i, 10)	
			elif op0.mnemonic == UD_Isub and\
				op0.operand[1].type == UD_OP_IMM and op0.operand[1].lval.lval == 1 and\
				op1.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
				op0.operand[0].isSame( op1.operand[0] ):
				op0.mnemonic = UD_Ineg
				op0.operand[1] = ud_operand()
				op1.mnemonic = UD_Inone
				self.DebugErrModify(i, 2, 2)
				self.Cleaner(i, 10)	

	def Round12_4(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		
		if op0.mnemonic == UD_Ipush and op1.mnemonic == UD_Isub and op2.mnemonic == UD_Imov and\
		   op3.mnemonic == UD_Iadd and op0.operand[0].type == UD_OP_IMM and\
		   op1.operand[0].type == UD_OP_MEM and op1.operand[0].size == 8 and\
		   op1.operand[1].type == UD_OP_REG and\
		   op2.operand[0].type == UD_OP_REG and op2.operand[1].type == UD_OP_MEM and\
		   op2.operand[1].size == 8 and\
		   op3.operand[0].type == UD_OP_REG and op3.operand[1].type == UD_OP_IMM and\
		   op0.operand[0].lval.lval == 0 and\
		   op1.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and\
		   op1.operand[1].base not in (UD_R_ESP, UD_R_RSP) and\
		   op1.operand[1].base == op2.operand[0].base and\
		   op2.operand[1].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)) and\
		   op3.operand[0].base in (UD_R_ESP, UD_R_RSP) and\
		   op3.operand[1].lval.udword == op0.operand[0].size // 8 and\
		   op0.operand[0].size in (16, 32, 64):
			op0.mnemonic = UD_Ineg
			op0.operand[0] = op1.operand[1].Copy()
			op1.mnemonic = UD_Inone
			op2.mnemonic = UD_Inone
			op3.mnemonic = UD_Inone
			self.DebugErrModify(i, 4, 0)
			self.Cleaner(i, 10)	
		   

	def Round12_5(self, i):
		op0 = self.heap[i].instr
		op1 = self.heap[i+1].instr
		op2 = self.heap[i+2].instr
		op3 = self.heap[i+3].instr
		op4 = self.heap[i+4].instr
		
		if op0.mnemonic == UD_Ipush and\
		   op1.mnemonic == UD_Imov and\
		   op2.mnemonic == UD_Isub and\
		   op3.mnemonic in (UD_Imov, UD_Ixchg) and\
		   op4.mnemonic == UD_Ipop and\
		   op0.operand[0].type == UD_OP_REG and op1.operand[0].type == UD_OP_REG and\
		   op1.operand[1].type == UD_OP_IMM and op2.operand[0].type == UD_OP_REG and\
		   op2.operand[1].type in (UD_OP_REG, UD_OP_MEM) and\
		   op3.operand[0].type in (UD_OP_REG, UD_OP_MEM) and\
		   op3.operand[1].type in (UD_OP_REG, UD_OP_MEM) and\
		   op4.operand[0].type == UD_OP_REG and\
		   op1.operand[1].lval.lval == 0 and\
		   SameBaseAndBigger(op0.operand[0], op1.operand[0]) and\
		   op1.operand[0].base == op2.operand[0].base and\
		   op2.operand[0].base != op2.operand[1].base and\
		   op0.operand[0].base == op4.operand[0].base:
			if op3.mnemonic == UD_Imov and\
			   op3.operand[1].base == op2.operand[0].base and\
			   op3.operand[0].isSame( op2.operand[1] ):
			   
				op0.mnemonic = UD_Ineg
				op0.CopyPrefixes(op2)
				op0.operand[0] = op2.operand[1].Copy()
				op1.mnemonic = UD_Inone
				op2.mnemonic = UD_Inone
				op3.mnemonic = UD_Inone
				op4.mnemonic = UD_Inone
				self.DebugErrModify(i, 5, 0)
				self.Cleaner(i, 10)
				
			elif op3.mnemonic == UD_Ixchg and\
			   ((op2.operand[1].isSame( op3.operand[0] ) and\
				 op2.operand[0].base == op3.operand[1].base) or\
			    (op2.operand[1].isSame( op3.operand[1] ) and\
				 op2.operand[0].base == op3.operand[0].base)):
				 
				op0.mnemonic = UD_Ineg
				op0.CopyPrefixes(op2)
				op0.operand[0] = op2.operand[1].Copy()
				op1.mnemonic = UD_Inone
				op2.mnemonic = UD_Inone
				op3.mnemonic = UD_Inone
				op4.mnemonic = UD_Inone
				self.DebugErrModify(i, 5, 1)
				self.Cleaner(i, 10)
		   

	
	def Round1(self):
		i = 0
		while i < self.count:
			self.CheckRound1_1(i)
			self.CheckRound1_2(i)
			self.CheckRound1_3(i)
			i += 1
	
	def Round2(self):
		i = self.count - 1
		while i >= 0:
			self.CheckRound2_1(i)
			i -= 1
	
			
	def Round3(self):
		i = self.count - 1
		while i >= 0:
			self.CheckRound3_1(i)
			i -= 1
	
	def Round4(self):
		i = self.count - 1
		while i >= 0:
			self.CheckRound4_1(i)
			self.CheckRound4_2(i)
			self.CheckRound4_3(i)
			i -= 1
	
	def Round5(self):
		i = self.count - 1
		while i >= 0:
			self.CheckRound5_1(i)
			self.CheckRound5_2(i)
			self.CheckRound5_3(i)
			self.CheckRound5_4(i)
			i -= 1
	
	def Round6(self):
		i = self.count - 1
		while i >= 0:
			self.CheckRound6_1(i)
			self.CheckRound6_2(i)
			self.CheckRound6_3(i)
			i -= 1
	
	def Round7(self):
		i = 0
		while i < self.count:
			self.CheckRound7_1(i)
			self.CheckRound7_2(i)
			self.CheckRound7_3(i)
			self.CheckRound7_4(i)
			i += 1
	
	def Round8(self):
		i = 0
		while i < self.count:
			self.CheckRound8_1(i)
			i += 1
	
	def Round9(self):
		i = 0
		while i < self.count:			
			self.Round9_1(i)
			self.Round9_2(i)
			i += 1
	
	def Round11(self):
		i = self.count - 1
		while i >= 0:
			self.CheckRound11_1(i)
			i -= 1
	
	def Round12(self):
		i = 0
		while i < self.count:
			self.Round12_1(i)
			self.Round12_2(i)
			self.Round12_3(i)
			self.Round12_4(i)
			self.Round12_5(i)
			i += 1


	def Clear_MovV2(self):
		i = 0
		while i < self.count:
			op = self.heap[i].instr
			if op.mnemonic == UD_Imov and op.operand[0].type == UD_OP_REG and op.operand[1].type == UD_OP_REG and\
			   op.operand[0].base == op.operand[1].base:
			   op.mnemonic = UD_Inone
			i += 1

		self.Cleaner()

	def PushMovEsp(self):
		i = 0
		while i < self.count:
			if not self.Bounds(i, 1):
				break

			op0 = self.heap[i].instr
			op1 = self.heap[i + 1].instr
			if op0.mnemonic == UD_Ipush and \
			   op1.mnemonic == UD_Imov and \
			   op1.operand[0].BISO() in ((UD_R_ESP, 0, 0, 0), (UD_R_RSP, 0, 0, 0)):
				op0.operand[0] = op1.operand[1].Copy()
		 		op1.mnemonic = UD_Inone
			i += 1

		self.Cleaner()

	def PushADPopAD(self):
		i = 0
		while i < self.count:
			if not self.Bounds(i, 1):
				break

			op0 = self.heap[i].instr
			op1 = self.heap[i + 1].instr
			if op0.mnemonic == UD_Ipusha and \
			   op1.mnemonic == UD_Ipopa:
				op0.mnemonic = UD_Inone
		 		op1.mnemonic = UD_Inone
			i += 1

		self.Cleaner()

	def RemoveJunk(self):
		i = 0
		while i < self.count:

			op0 = self.heap[i].instr
			#jcc next instruction
			if op0.mnemonic in JCC_LIST and \
			   op0.operand[0].lval.lval == 0:
				op0.mnemonic = UD_Inone

			if op0.mnemonic == UD_Irdtsc:
				op0.mnemonic = UD_Inone
			i += 1

		self.Cleaner()
	
	
	def SimpleA(self, a, vm, dbg = False):
		if dbg:
			self.RebuildInfo()
			xlog("")
			for l in self.GetListing(True, False):
				xlog(l)
		it = 0
		while True:
			cnt = self.count

			self.log.append("{}".format(it))
			
			self.Round1()
			self.Round2()
			self.Round3()
			self.Round4()
			self.Round5()
			self.Round6()
			self.Round7()
			self.Round8()
			self.Round9()
			
			
			self.Round11()
			self.Round12()


			#self.Cleaner()

			#ipos = self.GetOpPos(0x10ee26fd)
			#if ipos >= 0:
			#	Recompute( self.heap[ipos:ipos + 20] )
			
			#xlog("cnt {} {}".format(cnt, self.count))

			it += 1

			if dbg:
				xlog("cnt {} {}".format(cnt, self.count))
				self.RebuildInfo()
				for l in self.GetListing(True, False):
					xlog(l)

			if cnt == self.count:
				self.CollapseArithmetic(vm.tp)

				if cnt == self.count:
					break
	
	def SimpleB(self, a, vm, dbg = False):
		pass
	
	def SimpleC(self, a, vm, dbg = False):
		if dbg:
			self.RebuildInfo()
			xlog("")
			for l in self.GetListing(True, False):
				xlog(l)
		while True:
			cnt = self.count

			self.Round1()
			self.Round2()
			self.Round3()
			self.Round4()
			self.Round5()
			self.Round6()
			self.Round7()
			self.Round8()
			self.Round9()

			self.Round11()
			self.Round12()

			# self.Cleaner()

			# ipos = self.GetOpPos(0x10ee26fd)
			# if ipos >= 0:
			#	Recompute( self.heap[ipos:ipos + 20] )

			# xlog("cnt {} {}".format(cnt, self.count))

			if dbg:
				xlog("cnt {} {}".format(cnt, self.count))
				self.RebuildInfo()
				for l in self.GetListing(True, False):
					xlog(l)

			if cnt == self.count:
				self.CollapseArithmetic(vm.tp)

				if cnt == self.count:
					self.Clear_MovV2()

				if cnt == self.count:
					break

	def SimpleD(self, a, vm, dbg = False):
		if dbg:
			self.RebuildInfo()
			xlog("")
			for l in self.GetListing(True, False):
				xlog(l)
		while True:
			cnt = self.count

			self.Round1()
			self.Round2()
			self.Round3()
			self.Round4()
			self.Round5()
			self.Round6()
			self.Round7()
			self.Round8()
			self.Round9()

			self.Round11()
			self.Round12()

			if dbg:
				xlog("cnt {} {}".format(cnt, self.count))
				self.RebuildInfo()
				for l in self.GetListing(True, False):
					xlog(l)

			if cnt == self.count:
				self.CollapseArithmetic(vm.tp)
				self.RemoveJunk()
				self.PushADPopAD()

				if cnt == self.count:
					self.Clear_MovV2()

				if cnt == self.count:
					self.PushMovEsp()

				if cnt == self.count:
					break
	
	def Simple(self, vm, a, mode, dbg = False):
		if mode == 'A':
			self.SimpleA(a, vm, dbg)
		elif mode == 'B':
			self.SimpleB(a, vm, dbg)
		elif mode == 'C':
			self.SimpleC(a, vm, dbg)
		elif mode == 'D':
			self.SimpleD(a, vm, dbg)

	def GetListing(self, adr, jmp, idx = False, skip = False):
		outlst = list()

		for i in range(self.count):
			cmd = self.heap[i]
			instr = cmd.instr
			txt = udTranslateIntel(instr, True)
			if txt != "":

				if idx:
					txt = "{:d} \t".format(i) + txt
				if adr:
					txt = "{:08X} \t".format(cmd.addr) + txt

				if jmp:
					if instr.mnemonic == UD_Icall and instr.operand[0].type == UD_OP_IMM:
						txt += "({:08X})".format( UDWORD(instr.operand[0].lval.udword + 5 + cmd.addr) )
					elif instr.mnemonic == UD_Ijmp and instr.operand[0].type == UD_OP_IMM:
						if instr.operand[0].size == 8:
							txt += "({:08X})".format(UDWORD(instr.operand[0].lval.ubyte + 1 + cmd.addr))
						else:
							txt += "({:08X})".format(UDWORD(instr.operand[0].lval.udword + 5 + cmd.addr))
					elif instr.mnemonic in JCC_LIST and instr.operand[0].type == UD_OP_IMM:
						if instr.operand[0].size == 8:
							txt += "({:08X})".format(UDWORD(instr.operand[0].lval.ubyte + 2 + cmd.addr))
						else:
							txt += "({:08X})".format(UDWORD(instr.operand[0].lval.udword + 6 + cmd.addr))

				outlst.append(txt)
			elif not skip:
				xlog("GetListing ERROR {:x} at {:x}".format(cmd.instr.mnemonic, cmd.addr))
				#xlog("\t ID {:x}   op0 {:x} : {:x} ({:x})   op1 {:x} : {:x} ({:x}) ".format(cmd.instr.mnemonic, cmd.instr.operand[0].type, cmd.instr.operand[0].lval.lval, cmd.instr.operand[0].val2,
				#																			 cmd.instr.operand[1].type, cmd.instr.operand[1].value, cmd.instr.operand[1].val2))
				#XrkAsm.dbg = True
				#_ = XrkAsm.AsmRk(cmd.instr)
				#XrkAsm.dbg = False
				break
			else:
				pass
				#outlst.append("ID {:x}   op0 {:x} : {:x} ({:x})   op1 {:x} : {:x} ({:x}) ".format(cmd.instr.mnemonic, cmd.instr.operand[0].ID, cmd.instr.operand[0].value, cmd.instr.operand[0].val2,
				#																			 cmd.instr.operand[1].ID, cmd.instr.operand[1].value, cmd.instr.operand[1].val2))

		return outlst

	def RebuildInfo(self):
		for i in range(self.count):
			#rk = self.heap[i].instr
			#rk.opInfo = XrkAsm.FindInfo(rk)
			pass

	def FindConditionStart(self):
		opz = self.heap[self.count - 1].instr

		i = self.count - 1
		while i >= 0:
			op = self.heap[i].instr
			if op.mnemonic not in (MOVCLASS + IDNNCLASS + ASXORCLASS):
				return (0, 0, 0)

			if op.mnemonic in (MOVCLASS + ASXORCLASS):
				if op.operand[0].type not in (UD_OP_REG, UD_OP_MEM):
					return (0, 0, 0)
				if op.operand[1].type != UD_OP_IMM:
					return (0, 0, 0)

				if op.operand[0].BISO() != opz.operand[0].BISO() or\
				   op.operand[0].lval.lval != opz.operand[0].lval.lval:
					return (0, 0, 0)

				if IsOpClass(op, 0, 1, 0):
					return (1, i, op.operand[1].lval.lval)

			if not IsOpClass(op, 0, 1, 0):
				if op.operand[0].type not in (UD_OP_REG, UD_OP_MEM):
					return (0, 0, 0)

				if op.operand[0].BISO() != opz.operand[0].BISO() or \
				   op.operand[0].lval.lval != opz.operand[0].lval.lval:
					return (0, 0, 0)

			i -= 1
		return (2, 0, 0)

	def NextOpPos(self, op, startn = 0):
		if not isinstance(op, (list, tuple)):
			op = (op,)

		i = startn
		while i < self.count:
			if self.heap[i].instr.mnemonic in op:
				return i
			i += 1
		return -1

	def GetAddr(self, addr):
		for i in range(self.count):
			if self.heap[i].addr == addr:
				return self.heap[i]
		return None

	def EvaluateBranch(self, vm, opid, inz, mode):
		self.unk = 1
		opz = self.heap[self.count - 1].instr
		uvr4 = 0
		if opz.mnemonic == UD_Imov:
			return (0, inz)
		elif opz.mnemonic == UD_Icmp:
			return (1, inz)
		elif opz.mnemonic == UD_Itest:
			return (0x101, inz)
		elif opz.mnemonic == UD_Ior and opz.operand[0].type == UD_OP_REG and opz.operand[1].type == UD_OP_REG and \
				opz.operand[0].base == opz.operand[1].base:
			return (1, inz)
		else:
			(a, b, val) = self.FindConditionStart()
			if a == 0:
				self.Simple(vm, 0xfffe, mode)
				(a, b, val) = self.FindConditionStart()
				if a == 0:
					return (0, inz)
			l = b
			FLG = EFlags()
			while l < self.count - 1:
				op = self.heap[l].instr
				CalcEFlags(op.mnemonic, op.operand[0].size, val, op.operand[1].lval.lval, FLG)
				_, val = ComputeVal(op.mnemonic, op.operand[0].size, val, op.operand[1].lval.lval)

				inz = EvaluateJcc(opid, FLG)
				l += 1
		self.unk = 0
		return (1, inz)

	def NextOp0Reg(self, i, reg):
		while i < self.count:
			cmd = self.heap[i]
			if cmd.instr.operand[0].type == UD_OP_REG and cmd.instr.operand[0].base == reg:
				return (i, cmd)
			i += 1
		return (-1, None)

	def NextOp1MemReg(self, i, reg):
		while i < self.count:
			cmd = self.heap[i]
			if cmd.instr.operand[1].type == UD_OP_MEM and cmd.instr.operand[1].base == reg:
				return (i, cmd)
			i += 1
		return (-1, None)

	def NextOp0MemReg(self, i, reg):
		while i < self.count:
			cmd = self.heap[i]
			if cmd.instr.operand[0].type == UD_OP_MEM and cmd.instr.operand[0].base == reg:
				return (i, cmd)
			i += 1
		return (-1, None)

	def Bounds(self, offset, ln = 0):
		if offset >= 0 and ln >= 0:
			return offset + ln < self.count
		return False

	def SortByAddr(self):
		self.heap[:self.count] = sorted(self.heap[:self.count], key = lambda x : x.addr)


CMDSimpler = InsList()
	
	