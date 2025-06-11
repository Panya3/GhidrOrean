MAX_INSN_LENGTH = 15
P_none = 0

P_inv64 =        ( 1 << 0 )
def P_INV64(n):
    return ( ( n >> 0 ) & 1 )

P_def64 =        ( 1 << 1 )
def P_DEF64(n):
    return ( ( n >> 1 ) & 1 )

P_oso =          ( 1 << 2 )
def P_OSO(n):
    return ( ( n >> 2 ) & 1 )

P_aso =          ( 1 << 3 )
def P_ASO(n):
    return ( ( n >> 3 ) & 1 )

P_rexb =         ( 1 << 4 )
def P_REXB(n):
    return ( ( n >> 4 ) & 1 )

P_rexw =         ( 1 << 5 )
def P_REXW(n):
    return ( ( n >> 5 ) & 1 )

P_rexr =         ( 1 << 6 )
def P_REXR(n):
    return( ( n >> 6 ) & 1 )

P_rexx =         ( 1 << 7 )
def P_REXX(n):
    return ( ( n >> 7 ) & 1 )

P_seg =          ( 1 << 8 )
def P_SEG(n):
    return ( ( n >> 8 ) & 1 )

P_vexl =         ( 1 << 9 )
def P_VEXL(n):
    return ( ( n >> 9 ) & 1 )

P_vexw =         ( 1 << 10 )
def P_VEXW(n):
    return ( ( n >> 10 ) & 1 )

P_str =          ( 1 << 11 )
def P_STR(n):
    return ( ( n >> 11 ) & 1 )

P_strz =         ( 1 << 12 )
def P_STR_ZF(n):
    return ( ( n >> 12 ) & 1 )


OP_NONE = 0
OP_A = 1
OP_E = 2
OP_M = 3
OP_G = 4       
OP_I = 5
OP_F = 6
OP_R0 = 7
OP_R1 = 8
OP_R2 = 9
OP_R3 = 10
OP_R4 = 11
OP_R5 = 12
OP_R6 = 13
OP_R7 = 14
OP_AL = 15
OP_CL = 16
OP_DL = 17
OP_AX = 18
OP_CX = 19
OP_DX = 20
OP_eAX = 21
OP_eCX = 22
OP_eDX = 23
OP_rAX = 24
OP_rCX = 25
OP_rDX = 26
OP_ES = 27
OP_CS = 28
OP_SS = 29
OP_DS = 30
OP_FS = 31
OP_GS = 32
OP_ST0 = 33
OP_ST1 = 34
OP_ST2 = 35
OP_ST3 = 36
OP_ST4 = 37
OP_ST5 = 38
OP_ST6 = 39
OP_ST7 = 40
OP_J = 41
OP_S = 42
OP_O = 43
OP_I1 = 44
OP_I3 = 45
OP_sI = 46
OP_V = 47
OP_W = 48
OP_Q = 49
OP_P = 50
OP_U = 51
OP_N = 52
OP_MU = 53
OP_H = 54
OP_L = 55
OP_R = 56
OP_C = 57
OP_D = 58
OP_MR = 59


SZ_NA  = 0
SZ_Z   = 1
SZ_V   = 2
SZ_Y   = 3
SZ_X   = 4
SZ_RDQ = 7
SZ_B   = 8
SZ_W   = 16
SZ_D   = 32
SZ_Q   = 64
SZ_T   = 80
SZ_O   = 12
SZ_DQ  = 128
SZ_QQ  = 256


SZ_BD = ((SZ_B << 8) | SZ_D)
SZ_BV = ((SZ_B << 8) | SZ_V)
SZ_WD = ((SZ_W << 8) | SZ_D)
SZ_WV = ((SZ_W << 8) | SZ_V)
SZ_WY = ((SZ_W << 8) | SZ_Y)
SZ_DY = ((SZ_D << 8) | SZ_Y)
SZ_WO = ((SZ_W << 8) | SZ_O)
SZ_DO = ((SZ_D << 8) | SZ_O)
SZ_QO = ((SZ_Q << 8) | SZ_O)

def Mx_mem_size(size):
    return (size >> 8) & 0xff

def Mx_reg_size(size):
    return size & 0xff

class ud_itab_entry_operand:
    type = 0
    size = 0

    def __init__(self, t = 0, s = 0):
        self.type = t
        self.size = s

class ud_itab_entry:
    mnemonic = 0
    operand1 = None
    operand2 = None
    operand3 = None
    operand4 = None
    prefix = 0

    def __init__(self, m = 0, o1 = None, o2 = None, o3 = None, o4 = None, p = 0):
        self.mnemonic = m
        if o1 == None:
            o1 = ud_itab_entry_operand()
        if o2 == None:
            o2 = ud_itab_entry_operand()
        if o3 == None:
            o3 = ud_itab_entry_operand()
        if o4 == None:
            o4 = ud_itab_entry_operand()
        self.operand1 = o1
        self.operand2 = o2
        self.operand3 = o3
        self.operand4 = o4
        self.prefix = p

class ud_lookup_table_list_entry:
    table = None
    type = 0
    meta = None

    def __init__(self, tb = 0, tt = 0, m = 0):
        self.table = tb
        self.type = tt
        self.meta = m
