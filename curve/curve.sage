p = 2^252 + 27742317777372353535851937790883648493
F = GF(p)

def montgomery_to_weierstrass(A, B):
    a = 1/B^2 - A^2 / (3 * B^2)
    b = (2 * A^3 - 9 * A) / (27 * B^3)
    return (a, b)

def edwards_to_montgomery(a, d):
    A = 2 * (a + d) / (a - d)
    B = 4 / (a - d)
    return (A, B)

def edwards_add(d, x1, y1, x2, y2):
    x0 = (x1 * y2 + x2 * y1) / (1 + d * x1 * x2 * y1 * y2)
    y0 = (y1 * y2 - x1 * x2) / (1 - d * x1 * x2 * y1 * y2)
    assert x0^2 + y0^2 == 1 + d*x0^2*y0^2
    return (x0, y0)

def edwards_scale(d, s, x0, y0):
    xr = F(0)
    yr = F(1)
    xs = x0
    ys = y0

    assert x0^2 + y0^2 == 1 + d*x0^2*y0^2
    assert xr^2 + yr^2 == 1 + d*xr^2*yr^2
    assert edwards_add(d, xr, yr, x0, y0) == (x0, y0)

    s = int(s)
    while s:
        if s & 1 == 1:
            xr, yr = edwards_add(d, xr, yr, xs, ys)
        xs, ys = edwards_add(d, xs, ys, xs, ys)
        s >>= 1

    return (xr, yr)

def solve(d, x):
    y = sqrt((x^2 - 1) / (d * x^2 - 1))
    assert x^2 + y^2 == 1 + d*x^2*y^2
    return (x, y)

def hash_field(s: str):
    return F(int(hashlib.sha256(s.encode('utf-8')).hexdigest(), 16))

def hash_point(d, s: str):
    n = 0
    while 1:
        x = hash_field(s + '-' + str(n))
        w = (x^2 - 1) / (d * x^2 - 1)
        print(w)
        if w.is_square():
            x, y = solve(d, x)
            return edwards_scale(d, cofactor, x, y)
        else:
            n += 1

def point_weierstrass_to_montgomery(x, y):
    return (x / y, (x-1) / (x+1))

def point_montgomery_to_edwards(A, B, x, y):
    return (B * x - A / 3, B * y)

# x^2 y^2 = 1 + d*x^2 y^2
# x^2 y^2 - 1 = d*x^2 y^2

a = 1
d = -F(698)

cofactor = 4

import hashlib

(x0, y0) = hash_point(d, 'point1')
(x1, y1) = hash_point(d, 'point2')

A, B = edwards_to_montgomery(a, d)
a, b = montgomery_to_weierstrass(A, B)

E = EllipticCurve([a,b])
l = int(E.order() / cofactor)

assert edwards_scale(d, l, x0, y0) == (F(0), F(1))
assert edwards_scale(d, l, x1, y1) == (F(0), F(1))

assert is_prime(l)

edwards_scale(d, l, x0, y0)
