from typing import Tuple

import libnacl as nacl


def create_server_keys() -> Tuple[Tuple[bytes, bytes], Tuple[bytes, bytes]]:
    verkey, sk = nacl.crypto_sign_ed25519_keypair()
    curve_pk = nacl.crypto_sign_ed25519_pk_to_curve25519(verkey)
    curve_sk = nacl.crypto_sign_ed25519_sk_to_curve25519(sk)
    return (verkey, sk), (curve_pk, curve_sk)
