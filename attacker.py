import socket
import pickle
from ecdsa.ecdsa import curve_128r1
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from sage.all import EllipticCurve, GF, crt

def decrypt_data(shared_point, ciphertext):
    if shared_point.is_zero():
        x, y = 0, 0
    else:
        x, y = shared_point.xy()
    key = long_to_bytes(int(x)).rjust(16, b"\x00")
    iv = long_to_bytes(int(y)).rjust(16,b"\x00")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, 16)

def brute_force_encrypted_message(A, ciphertext, max_order):
    for i in range(1, max_order):
        shared_point = i*A
        try:
            decrypted = decrypt_data(shared_point, ciphertext)
            decrypted = decrypted.decode()
            return i
        except:
            continue
    raise Exception("Did not find a value for one fo the encrypted messages")
def find_curves_with_small_subgroup(p, a, max_order):
    orders_found = set()
    b = 0
    while True:
        b+=1
        if b==p:
            break
        if (4*a^3 + 27*b^2) % p == 0:
            continue
        try:
            E = EllipticCurve(GF(p), [a, b])
        except ArithmeticError:
            continue
        for _ in range(100):
            R = E.random_point()
            n = R.order()
            for f,e in n.factor():
                if f in orders_found:
                    continue
                if f > max_order:
                    break
                orders_found.add(f)
                P = (n // f)*R
                assert P.order() == f
                yield (f,P,b)

def main(host="10.10.10.10", port=9999):
    subsolutions = []
    subgroup = []
    max_order = 10000
    upto = 1

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        


    s.connect((host, port))

    # Nhận tham số đường cong từ server
    data = s.recv(4096)
    params = pickle.loads(data)
    p = params['p']
    a = params['a']
    b = params['b']
    Gx, Gy = params['G']
    E = EllipticCurve(GF(p), [a, b])
    G = E(Gx, Gy)
    n = G.order()
    print(f"    p = {p}")
    print(f"    a = {a}")
    print(f"    G = ({Gx}, {Gy})")

    for order, A,b in find_curves_with_small_subgroup(p,a,max_order):
        upto *= order
        print("Found point with order", order, "so now can find keys of size up to", upto)
        x, y  = A.xy()
        s.send(pickle.dumps((int(x), int(y),int(b))))

        ciphertext = s.recv(1024)
        print(f"[+] Received ciphertest for order {order}: {ciphertext.hex()}")

        key_mod_order = brute_force_encrypted_message(A, ciphertext, max_order)
        subsolutions.append(key_mod_order)
        subgroup.append(order)

        if upto >= n:
            break
    print("Found enough values! Running CRT...")
    found_key = crt(subsolutions, subgroup)
    print("Found private key", found_key)
    s.close()

if __name__ == "__main__":
    main()
