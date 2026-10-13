def make_commitments(coefficients:list[int],g:int,p:int) ->list[int]:
    if not coefficients:
        raise ValueError("系数列表不能为空")
    return [pow(g,coef,p) for coef in coefficients]

def verify_share(share:int,node_id:int,commitments:list[int],g:int,p:int)->bool:
    if node_id <= 0 :
        raise ValueError(f"节点编号从1开始，收到非法编号：{node_id}")
    if not commitments:
        raise ValueError("承诺列表不能为空")

    lhs = pow(g,share,p)
    rhs = 1
    current_power = 1
    for c_k in commitments:
        term = pow(c_k,current_power,p)
        rhs = (rhs * term) % p
        current_power = current_power * node_id
    return lhs == rhs
