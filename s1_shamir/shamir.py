import secrets
from s1_shamir.field import add_mod, inv_mod, mul_mod
from s1_shamir.polynomial import evaluate_polynomial

def generate_polynomial(secret:int,threshold:int,p:int) ->list[int]:
    #c0为秘密
    coeffs = [secret % p]
    for _ in range(threshold-1):
        coeffs.append(secrets.randbelow(p))
    return coeffs

#生成份额
def generate_shares(
        coeffs:list[int],
        participants:int,
        p:int
) ->list[tuple[int,int]]:
    shares = []
    for node_id in range(1,participants+1):
        y = evaluate_polynomial(coeffs,node_id,p)
        shares.append((node_id,y))
    return shares

#以下模块存疑
def lagrange_coefficient_at_zero(
        target_x:int,
        selected_xs:list[int],
        p:int
) ->int:
    """计算单个参与方 target_x 在 x=0 处的拉格朗日插值基系数 lambda_{target_x}(0) mod p。

        公式: prod_{m in selected, m != target_x} (-m) / (target_x - m) mod p
        """
    num = 1
    den = 1
    for m in selected_xs:
        if m == target_x:
            continue
        num = mul_mod(num,-m,p)
        den = mul_mod(den,target_x-m,p)
    return mul_mod(num,inv_mod(den,p),p)

def reconstruct_secret(
        shares:list[tuple[int,int]],threshold:int,p:int
)->int:
    if len(shares)<threshold:
        raise ValueError(f"份额数量不足: 需要至少 {threshold} 个，实际只有 {len(shares)} 个")
    selected_shares = shares[:threshold]
    xs = [x for x,_ in selected_shares]

    if len(set(xs)) != len(xs):
        raise  ValueError("提供份额包含重复节点编号（x）")

    recovered_secret = 0
    for x_j,y_j in selected_shares:
        coeff = lagrange_coefficient_at_zero(x_j,xs,p)
        term = mul_mod(y_j,coeff,p)
        recovered_secret = add_mod(recovered_secret,term,p)
    return recovered_secret
