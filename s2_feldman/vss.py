import secrets
from commitment import make_commitments

def generate_vss_shares(
        secret:int,
        threshold:int,
        participants:int,
        g:int,
        p:int,
        q:int,
) -> tuple[list[int],list[tuple[int,int]]]:

    if threshold > participants:
        raise ValueError("门限不能大于参与方总数")
    # 1. 在 Z_q 内随机选取度数为 threshold - 1 的多项式
    coefficients = [secret % q]
    for _ in range(threshold -1):
        coefficients.append(secrets.randbelow(q))

    #计算公开承诺
    commitments = make_commitments(coefficients,g,p)

    #计算每个节点份额
    shares = []
    for node_id in range(1,participants+1):
        y = 0
        for coef in reversed(coefficients):
            y = (y * node_id + coef) % q
        shares.append((node_id, y))
    return commitments, shares



