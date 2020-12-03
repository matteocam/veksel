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

def largest_square_div(n):
    s = 1
    print('factor')
    for (p, m) in list(factor(n)):
        print(p, m)
        s *= p^(floor(m / 2))
    return s

# p : size of prime field
# o : rational places on curve
def cm_discreminant(p, o):
    # calculate trace
    t = p + 1 - o
    print('trace:', t)

    # CM field discriminant
    s = largest_square_div(t^2 - 4*p)
    I = (t^2 - 4 * p) / (s^2)
    if I % 4 == 1:
        return I
    return 4 * I


w = 1
d = F(1)

while 1:
    a = 1
    w = w + 1
    for v in range(1, w):
        d = F(v) / F(w)

        print(d, '=', v, '/', w)

        if d.is_square():
            continue

        print('Edwards Coefficients:', a, d)

        A, B = edwards_to_montgomery(a, d)
        a, b = montgomery_to_weierstrass(A, B)

        E = EllipticCurve([0,0,0,a,b])

        print(E)

        o = E.order()

        print('order:', o)

        assert o % 4 == 0, 'sanity check: necessary for point of order 4'

        # minimal cofactor of 4
        if not is_prime(o / 4):
            continue

        # order of large group
        l = o / 4

        # check SafeCurves criteria
        # https://safecurves.cr.yp.to/index.html

        # https://safecurves.cr.yp.to/rho.html
        print('check sufficient order')
        if 0.886 * sqrt(l) <= 2^100:
            print('bad protection against rho method')
            continue

        # https://safecurves.cr.yp.to/disc.html
        print('check cm discriminant')
        if abs(cm_discreminant(p, o)) <= 2^100:
            print('bad complex-multiplication field discriminant')
            continue
