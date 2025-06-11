from udis86_decode import *

def udLookupMnemonic(c):
    if (c < UD_MAX_MNEMONIC_CODE):
        return ud_mnemonics_str[c]
    else:
        return ""

# def Disasm(buf, mode = 32):
#     tmp = ud()
#     tmp.dis_mode = mode
#     tmp.setBuf(buf)
#     tmp.pc = 0x1008dfb7
#
#     tmp.decode()
#     return tmp
#
# def SynText(t):
#     udTranslateIntel(t, True)
#     return t.asm_buf
#
#
# if __name__ == "__main__":
#     buf = bytearray(b'\x58\x48\x89\xc3\x48\xff\xc0\x48\x2d\x00\x30\x4c\x00\x48\x2d\xaf\xe5\x77\x05\x48\x05\xa3\xe5\x77\x05\x80\x3b\xcc\x75\x19\xc6\x03\x00\xbb\x00\x10\x00\x00\x68\x17\x9e\x4f\x5c')
#     a = Disasm(buf , 64)
#     while a.error == 0 and a.inp_end == False:
#         print(SynText(a))
#         a.decode()
