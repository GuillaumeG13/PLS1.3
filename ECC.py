import random
from sha import sha256

class ECurve:

    def __init__(self):
        self.p0 = 2**256
        self.p1 = -189
        self.v = -3
        self.w = 152961
        self.Gen = ECurve.EPoint(105253582565059894136665861841922275289986629145388631647570749365572640546948,
                          96137476056738940893930759645003034760186494279474271611460405989544632011578,
                          1)
        self.order = 115792089237316195423570985008687907853233080465625507841270369819257950283813

    def new_point(self, x, y, z):
        point = self.EPoint(x, y, z)
        return point

    def make_pub_key(self, priv_key):
        pub_point = priv_key * self.Gen
        x = self.IntMod(pub_point.x).value
        y = self.IntMod(pub_point.y).value
        z = self.IntMod(pub_point.z).value
        pub_key = str(hex(x) + str(hex(y))[2:] + str(hex(z))[2:])
        print(pub_key)
        return pub_key

    @staticmethod
    def _make_priv_key():
        priv_key = random.randrange(2**256 - 1)
        return priv_key

    def key_gen(self):
        priv_key = ECurve._make_priv_key()
        pub_key = self.make_pub_key(priv_key)
        return hex(priv_key), pub_key

    def verify_signature(self, pub_key, pL, signature):
        pub_point = ECurve.pub_key_to_point(pub_key)
        if self.verify_point(pub_key) is not True:
            return False
        signature = signature[2:]
        r = int(signature[:15], 16)
        s = int(signature[16:], 16)
        if r < 1 or r > self.order - 1:
            return False
        if r < 1 or r > self.order - 1:
            return False
        e = sha256(pL)
        w = inverse(s, self.order)
        u1 = self.mul_mod_order(e, w)
        u2 = self.mul_mod_order(r, w)
        verification_point = u1 * self.Gen + u2 * pub_point
        if self.verify_point(verification_point) is not True:
            return False
        if r == verification_point.x.value:
            return True
        else:
            return False

    def verify_point(self, point):
        y = point.x * point.x * point.x + self.v * point.x + self.w
        y2 = (y * y).value
        nQ = self.order * point
        if point.z.value == 0:
            return False
        elif y2 != (point.y * point.y).value:
            return False
        elif nQ.z.value != 0:
            return False
        else:
            return True

    def mul_mod_order(self, a, b):
        # TODO: implement modular regression by the curve order (montgomery?) for signature and verification purpose
        return (a * b) % self.order

    @staticmethod
    def pub_key_to_point(pub_key):
        pub_key = pub_key[2:]
        x = int(pub_key[:15], 16)
        y = int(pub_key[16:31], 16)
        z = int(pub_key[32:47], 16)
        return ECurve.EPoint(x, y, z)

    class EPoint:

        def __init__(self, x, y, z):
            self.x = ECurve.IntMod(x)
            self.y = ECurve.IntMod(y)
            self.z = ECurve.IntMod(z)
            self.v = ECurve.IntMod(-3)

        def __add__(self, other):
            if self.y == -other.y:
                return ECurve.EPoint(0, 0, 0)
            # TODO: verify expression of Pinfinty
            else:
                a = other.y * self.z - self.y * other.z
                b = other.x * self.z - self.x * other.z
                c = a * a * self.z * other.z - b * b * b - 2 * b * b * self.x * other.z
                x3 = b*c
                y3 = a * (b * b * self.x * other.z - c) - b * b * b * self.y * other.z
                z3 = b * b * b * self.z * other.z
                return ECurve.EPoint(x3, y3, z3)

        def double(self):
            a = self.v * self.z*self.z + 3*self.x*self.x
            b = self.y * self.z
            c = self.x * self.y * b
            d = a*a - 8 * c
            x3 = 2 * b * d
            y3 = a * (4 * c - d) - 8 * self.y*self.y * b*b
            z3 = 8 * b*b*b
            return ECurve.EPoint(x3, y3, z3)

        def double_and_add(self, r):
            t = self
            r_bin = bin(r)[3:]
            n = len(r_bin)  # r_bin has already been truncated by 1
            for i in range(0, n):
                t = t.double()
                if r_bin[i] == '1':
                    t = t + self
            return t

        def __repr__(self):
            return str(self.x) + ", " + str(self.y) + ", " + str(self.z)

        def __mul__(self, scalar):
            try:
                if isinstance(scalar, int):
                    return self.double_and_add(scalar)
                else:
                    raise TypeError("All coordinates and attributes must be integers")
            except TypeError as error:
                print(error)

        __rmul__ = __mul__

    class IntMod(int):
        # TODO: test to know if we can delete the 'value' parameter; if not : verify that 'value' is always used

        def __init__(self, val):
            super().__init__()
            try:
                if isinstance(val, ECurve.IntMod):
                    self.value = val.value
                elif isinstance(val, int):
                    self.value = val
                else:
                    raise TypeError("All coordinates and attributes must be integers")
                self.p1 = -189
                self.p0 = 2 ** 256
            except TypeError as error:
                print(error)

        def __mul__(self, other):
            try:
                if isinstance(other, ECurve.IntMod):
                    c = self.value * other.value
                elif isinstance(other, int):
                    c = self.value * other
                else:
                    raise TypeError("All coordinates and attributes must be integers")
                return self.mod(c)
            except TypeError as error:
                print(error)

        __rmul__ = __mul__

        def __add__(self, other):
            c = self.value + other.value
            return self.mod(c)

        def __sub__(self, other):
            c = self.value - other.value
            return self.mod(c)

        def mod(self, c):
            if c > 0:
                while c > self.p0 + self.p1:
                    c_bin = bin(c)[2:]
                    n = len(c_bin)
                    c0 = c_bin[:n - 256]
                    c1 = c_bin[n - 256: n]
                    c = int(str(c1), 2) - int(str(c0), 2) * self.p1
            else:
                while c < 0:
                    if -c > self.p0 + self.p1:
                        c_bin = bin(c)[3:]  # - sign is forgotten
                        n = len(c_bin)
                        c0 = c_bin[:n - 256]
                        c1 = c_bin[n - 256: n]
                        c = self.p0 + self.p1 - int(str(c1), 2) + int(str(c0), 2) * self.p1
                    else:
                        c += self.p0 + self.p1
            return ECurve.IntMod(c)


def inverse(x, p):

    inv1 = 1
    inv2 = 0
    while p != 1 and p != 0:
        inv1, inv2 = inv2, inv1 - inv2 * (x / p)
        x, p = p, x % p
    return inv2

if __name__ == "__main__":
    E = ECurve()
    p1 = E.new_point(77512729778395059953025101417153080590899181236631402472091884972383820944632,
                     94020229094332693319282440533939091398265289073971107102474119362287069424263,
                     1)
    p2 = E.new_point(13019070506303776446905234734309302936538453543550789835093435313259936292994,
                     79305220390864306867010712884484812428033918505605812445812976903991773716321,
                     1)
    n = 115792089237316195423570985008687907853233080465625507841270369819257950283813
    Gen = E.new_point(105253582565059894136665861841922275289986629145388631647570749365572640546948,
                      96137476056738940893930759645003034760186494279474271611460405989544632011578,
                      1)
    E.make_pub_key(105253582565059894136665861841922275289986629145388631647570749365572640546948)
    # p3 = p1 + p2
    # print(p3)
    # p4 = p2.double()
    # print(p4)
    # p5 = 3 * p2
    # print(p5)

# TODO: implement better modular inverse

