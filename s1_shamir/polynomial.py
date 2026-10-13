from s1_shamir.field import add_mod, mul_mod

#秘密本身为c0
def evaluate_polynomial(coefficients:list[int],x:int,p:int) ->int:
    if not coefficients:
        raise ValueError("多项式系数列表不能为空")
    result = 0
    for coef in reversed(coefficients):
        result = add_mod(mul_mod(result,x,p),coef,p)
    return result
