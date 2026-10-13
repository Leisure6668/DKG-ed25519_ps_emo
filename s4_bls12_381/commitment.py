from py_ecc.optimized_bls12_381 import G1,eq,add,curve_order,multiply

def make_commitments(ceofficients:list[int])->list[tuple]:
    if not ceofficients:
        raise ValueError("系数列表不能为空")
    return [multiply(G1,c% curve_order) for c in ceofficients]

def verify_share (share:int,node_id:int,commitments:list[tuple])->bool:
    if node_id <= 0 :
        raise ValueError(f"节点编号必须从1开始，非法编号：{node_id}")
    if not commitments:
        raise ValueError("承诺列表不能为空")

    lhs = multiply(G1,share % curve_order)

    rhs = None
    power = 1
    for c_k in commitments:
        term = multiply(c_k,power)
        rhs = term if rhs is None else add(rhs,term)
        power = (power * node_id) % curve_order

    return eq(lhs,rhs)





