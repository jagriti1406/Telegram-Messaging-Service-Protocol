from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

def get_fixed_dh_parameters():
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
        "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F"
        "24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
    g = 2
    parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
    return parameters
