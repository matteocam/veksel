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


def check(i):
    a = 1
    d = F(i)

    if d.is_square():
        return None

    A, B = edwards_to_montgomery(a, d)
    a, b = montgomery_to_weierstrass(A, B)

    E = EllipticCurve([0,0,0,a,b])

    o = E.order()

    print(a, i, E, o)

    assert o % 4 == 0, 'sanity check: necessary for point of order 4'

    # minimal cofactor of 4
    if not ZZ(o / 4).is_prime():
        return None

    # order of large group
    l = o / 4

    # check SafeCurves criteria
    # https://safecurves.cr.yp.to/index.html

    # https://safecurves.cr.yp.to/rho.html
    print('check sufficient order')
    if 0.886 * sqrt(l) <= 2^100:
        print('bad protection against rho method')
        return None

    # https://safecurves.cr.yp.to/disc.html
    print('check cm discriminant')
    if abs(cm_discreminant(p, o)) <= 2^100:
        print('bad complex-multiplication field discriminant')
        return None

    return i

from itertools import chain
import multiprocessing as mp

if __name__ == '__main__':
    pool = mp.Pool()
    bound = 1_000_000_000_000

    positive = range(bound)
    negative = map(lambda x: -x, range(bound))
    params = chain.from_iterable(zip(positive, negative))

    for res in pool.imap(check, params):
        if res is not None:
            print('Result:', res)
            with open('found-d.txt', 'w') as f:
                f.write(str(res) + '\n')
            break
