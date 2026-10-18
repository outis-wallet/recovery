"""Independent, standard-library-only verifier for PUBLIC vectors. Not a secret-key tool.

Affine curve arithmetic here is deliberately simple and variable-time. Production recovery
uses the Rust implementation and its established crypto libraries instead.
"""
import hashlib
import hmac
import json
from pathlib import Path

P = 2**251 + 17 * 2**192 + 1
N = 3618502788666131213697322783095070105526743751716087489154079457884512865583
G = (874739451078007766457464989774322083649278607533249481151382481072868806602,
     152666792071518830868575557812948353041420400780739481342941381225525861407)
# Starknet's public Pedersen constants (shift, low/high first input, low/high second input).
# https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html
POINTS = [
    (2089986280348253421170679821480865132823066470938446095505822317253594081284,
     1713931329540660377023406109199410414810705867260802078187082345529207694986),
    (996781205833008774514500082376783249102396023663454813447423147977397232763,
     1668503676786377725805489344771023921079126552019160156920634619255970485781),
    (2251563274489750535117886426533222435294046428347329203627021249169616184184,
     1798716007562728905295480679789526322175868328062420237419143593021674992973),
    (2138414695194151160943305727036575959195309218611738193261179310511854807447,
     113410276730064486255102093846540133784865286929052426931474106396135072156),
    (2379962749567351885752724891227938183011949129833673362440656643086021394946,
     776496453633298175483985398648758586525933812536653089401905292063708816422),
]
LIMIT = 2**256 - (2**256 % N)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x + 1) * pow(2 * y, -1, P) if a == b
             else (v - y) * pow(u - x, -1, P)) % P
    new_x = (slope * slope - x - u) % P
    return new_x, (slope * (x - new_x) - y) % P


def multiply(point, scalar):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def pedersen(a, b):
    result = POINTS[0]
    for point, scalar in zip(POINTS[1:], [a % 2**248, a >> 248, b % 2**248, b >> 248]):
        result = add(result, multiply(point, scalar))
    return result[0]


def hash_elements(elements):
    result = 0
    for element in [*elements, len(elements)]:
        result = pedersen(result, element)
    return result


def hkdf(data, label):
    prk = hmac.digest(bytes(32), data, 'sha256')
    return hmac.digest(prk, label.encode('utf-8') + b'\x01', 'sha256')


def grind(material):
    for counter in range(100001):
        suffix = counter.to_bytes(max(1, (counter.bit_length() + 7) // 8), 'big')
        value = int.from_bytes(hashlib.sha256(material + suffix).digest(), 'big')
        if value < LIMIT:
            return value % N
    raise ValueError('No key')


def check_key(root, label, expected):
    private = grind(hkdf(root, label))
    assert private == int(expected['privateKey'], 16), label
    assert multiply(G, private)[0] == int(expected['publicKey'], 16), label
    return private


def viewing(private, chain, account, pool):
    context = b''.join(value.to_bytes(width, 'big') for value, width in
                       [(1, 4), (chain, 32), (account, 32), (pool, 32), (0, 16)])
    for counter in range(2**32):
        value = int.from_bytes(hmac.digest(private.to_bytes(32, 'big'),
            b'STRK20_ACCOUNT_LEAF_V1' + context + counter.to_bytes(4, 'big'), 'sha256'), 'big')
        if value >= LIMIT:
            continue
        scalar = value % N
        folded = min(scalar, N - scalar)
        if 1 <= folded < N // 2:
            return folded
    raise ValueError('No viewing key')


def main():
    fixture = Path(__file__).resolve().parent / 'fixtures/recovery-v1-vectors.json'
    vector = json.loads(fixture.read_text())
    seed = bytes.fromhex(vector['entropy'])
    # Independently decode this published BIP39 test phrase: abandon=0, about=3.
    words = {'abandon': 0, 'about': 3}
    encoded = ''.join(f"{words[word]:011b}" for word in vector['phrase'].split())
    assert int(encoded[:128], 2).to_bytes(16, 'big') == seed
    assert int(encoded[128:], 2) == hashlib.sha256(seed).digest()[0] >> 4
    root = hkdf(seed, 'outis/seed/v1')
    assert root.hex() == vector['root']
    for case in vector['accounts']:
        role = 'agent' if case['kind'] == 'agent' else 'owner'
        private = check_key(root, f"outis/{role}/v1/{case['network']}/{case['index']}", case['owner'])
        check_key(root, 'outis/vault/wallet/v1', case['vault'])
        chain = int.from_bytes(case['network'].encode('ascii'), 'big')
        assert chain == int(case['chainId'], 16)
        deploy = case['deployment']
        address = hash_elements([
            int.from_bytes(b'STARKNET_CONTRACT_ADDRESS', 'big'), int(deploy['deployer'], 16),
            int(deploy['salt'], 16), int(deploy['classHash'], 16),
            hash_elements([int(value, 16) for value in deploy['constructorCalldata']]),
        ]) % (2**251 - 256)
        assert address == int(case['address'], 16)
        if 'viewing' in case:
            v = case['viewing']
            assert viewing(private, chain, address, int(v['pool'], 16)) == int(v['privateKey'], 16)
    print(f"Independently verified {len(vector['accounts'])} public cases: seed, root, keys, addresses and viewing key")


if __name__ == '__main__':
    main()
