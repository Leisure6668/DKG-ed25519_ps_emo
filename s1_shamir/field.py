def add_mod(a:int,b:int,p:int) ->int:
    return (a+b) % p

def mul_mod(a:int,b:int,p:int) ->int:
    return (a*b) % p

def inv_mod(a:int,p:int) ->int:
    a_reduced = a % p
    if a_reduced == 0:
        raise ZeroDivisionError(f"0在模{p}下没有乘法逆元")
    return pow(a_reduced, -1, p)