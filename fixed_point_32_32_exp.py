# coding: utf-8
import math
RCP_LN2 = 0x171547652

def Qmul30(a, b):
    return a * b >> 30;

def Exp2Poly4(a):
    y = Qmul30(a, 14555373)
    y = Qmul30(a, y + 55869331)
    y = Qmul30(a, y + 259179547)
    y = Qmul30(a, y + 744137573)
    y = y + 1073741824
    return y

def Exp2Fast(x):
    k = int((x / 0x100000000) / 4)
    y = Exp2Poly4(k) * 4
    intPart = x / 0x100000000
    # You must use lookup table to implement 2**intPart for intPart in Z[-32, 32]
    return y * (2**(intPart))

def Mul(a, b):
    return a * b / 0x100000000

def Exp(x):
    return int(Exp2Fast(Mul(x, RCP_LN2)))

abs = lambda x: x if x >= 0 else -x
err = lambda x: abs((Exp(x * 0x100000000) / 0x100000000) - math.exp(x))

print(err(1))
print(err(-1.2))
print(err(-10))
print(err(-6))
print(err(10))
print(err(13))
print(err(14))
