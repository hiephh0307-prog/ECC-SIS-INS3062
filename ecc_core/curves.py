"""Elliptic curves over prime fields F_p with Affine and Jacobian coordinate arithmetic."""

from __future__ import annotations

from dataclasses import dataclass

from .field import mod_inv, mod_sqrt


@dataclass(frozen=True)
class EllipticCurve:
    """Short Weierstrass elliptic curve: y^2 = x^3 + a*x + b (mod p)."""

    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int
    h: int = 1
    bit_size: int = 256

    def __post_init__(self) -> None:
        if self.p <= 2:
            raise ValueError("Prime p must be > 2.")
        discriminant = (4 * pow(self.a, 3, self.p) + 27 * pow(self.b, 2, self.p)) % self.p
        if discriminant == 0:
            raise ValueError(f"Curve {self.name} is singular (discriminant == 0 mod p).")
        if not self.is_on_curve_coords(self.gx, self.gy):
            raise ValueError(f"Generator point G for {self.name} is not on the curve.")

    @property
    def byte_size(self) -> int:
        return (self.bit_size + 7) // 8

    @property
    def coord_byte_size(self) -> int:
        return (self.p.bit_length() + 7) // 8

    @property
    def order_byte_size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def G(self) -> Point:
        return Point(self, self.gx, self.gy, validate=False)

    @property
    def infinity(self) -> Point:
        return Point(self, None, None, validate=False)

    def is_on_curve_coords(self, x: int | None, y: int | None) -> bool:
        if x is None and y is None:
            return True
        if x is None or y is None:
            return False
        if not (0 <= x < self.p and 0 <= y < self.p):
            return False
        lhs = (y * y) % self.p
        rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        return lhs == rhs

    def enumerate_points(self) -> list[Point]:
        """Enumerate all points on small curves (only intended for educational/toy curves)."""
        if self.p > 2000:
            raise ValueError("Point enumeration is only supported for small curves (p <= 2000).")
        pts: list[Point] = []
        for x in range(self.p):
            rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
            y = mod_sqrt(rhs, self.p)
            if y is not None:
                pts.append(Point(self, x, y, validate=False))
                y2 = (-y) % self.p
                if y2 != y:
                    pts.append(Point(self, x, y2, validate=False))
        pts.append(self.infinity)
        return pts

    def decode_point(self, data: bytes) -> Point:
        """Decode SEC1 compressed (0x02/0x03) or uncompressed (0x04) point."""
        if not data:
            raise ValueError("Empty point encoding.")
        size = self.coord_byte_size
        prefix = data[0]

        if prefix == 0x00 and len(data) == 1:
            return self.infinity

        if prefix == 0x04:
            if len(data) != 1 + 2 * size:
                raise ValueError(f"Invalid uncompressed point length: expected {1 + 2 * size}, got {len(data)}.")
            x = int.from_bytes(data[1 : 1 + size], "big")
            y = int.from_bytes(data[1 + size :], "big")
            return Point(self, x, y, validate=True)

        if prefix in (0x02, 0x03):
            if len(data) != 1 + size:
                raise ValueError(f"Invalid compressed point length: expected {1 + size}, got {len(data)}.")
            x = int.from_bytes(data[1:], "big")
            if not (0 <= x < self.p):
                raise ValueError("x coordinate out of field range.")
            rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
            y = mod_sqrt(rhs, self.p)
            if y is None:
                raise ValueError("Invalid compressed point: x has no square root on curve.")
            is_odd = prefix == 0x03
            if (y % 2 == 1) != is_odd:
                y = (-y) % self.p
            return Point(self, x, y, validate=True)

        raise ValueError(f"Unsupported SEC1 point prefix: 0x{prefix:02x}")


class Point:
    """Affine point on an EllipticCurve over F_p."""

    __slots__ = ("curve", "x", "y")

    def __init__(self, curve: EllipticCurve, x: int | None, y: int | None, validate: bool = True) -> None:
        self.curve = curve
        self.x = x % curve.p if x is not None else None
        self.y = y % curve.p if y is not None else None
        if validate and not curve.is_on_curve_coords(self.x, self.y):
            raise ValueError(f"Point ({self.x}, {self.y}) is not on curve {curve.name}.")

    @property
    def is_infinity(self) -> bool:
        return self.x is None or self.y is None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False
        return self.curve.name == other.curve.name and self.x == other.x and self.y == other.y

    def __neg__(self) -> Point:
        if self.is_infinity:
            return self
        assert self.y is not None
        return Point(self.curve, self.x, (-self.y) % self.curve.p, validate=False)

    def __repr__(self) -> str:
        if self.is_infinity:
            return f"Point({self.curve.name}, Infinity)"
        return f"Point({self.curve.name}, x=0x{self.x:x}, y=0x{self.y:x})"

    def to_bytes(self, compressed: bool = False) -> bytes:
        """Encode point in SEC1 uncompressed (0x04||x||y) or compressed (0x02/0x03||x) form."""
        if self.is_infinity:
            return b"\x00"
        assert self.x is not None and self.y is not None
        size = self.curve.coord_byte_size
        x_bytes = self.x.to_bytes(size, "big")
        if compressed:
            prefix = b"\x03" if (self.y & 1) else b"\x02"
            return prefix + x_bytes
        y_bytes = self.y.to_bytes(size, "big")
        return b"\x04" + x_bytes + y_bytes

    def to_hex(self, compressed: bool = False) -> str:
        return self.to_bytes(compressed=compressed).hex()

    # ------------------------------------------------------------------
    # Affine Arithmetic
    # ------------------------------------------------------------------
    def add_affine(self, other: Point) -> Point:
        """Point addition using affine coordinates (requires 1 modular inversion)."""
        if self.curve.name != other.curve.name:
            raise ValueError("Cannot add points on different curves.")
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self

        p = self.curve.p
        assert self.x is not None and self.y is not None
        assert other.x is not None and other.y is not None

        if self.x == other.x:
            if (self.y + other.y) % p == 0:
                return self.curve.infinity
            return self.double_affine()

        slope = ((other.y - self.y) * mod_inv(other.x - self.x, p)) % p
        x3 = (slope * slope - self.x - other.x) % p
        y3 = (slope * (self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3, validate=False)

    def double_affine(self) -> Point:
        """Point doubling using affine coordinates."""
        if self.is_infinity or self.y == 0:
            return self.curve.infinity
        p = self.curve.p
        assert self.x is not None and self.y is not None
        slope = ((3 * self.x * self.x + self.curve.a) * mod_inv(2 * self.y, p)) % p
        x3 = (slope * slope - 2 * self.x) % p
        y3 = (slope * (self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3, validate=False)

    def scalar_mul_affine(self, k: int) -> Point:
        """Double-and-add scalar multiplication in affine coordinates."""
        if k < 0:
            return (-self).scalar_mul_affine(-k)
        if k == 0 or self.is_infinity:
            return self.curve.infinity
        result = self.curve.infinity
        addend = self
        while k > 0:
            if k & 1:
                result = result.add_affine(addend)
            addend = addend.double_affine()
            k >>= 1
        return result

    # ------------------------------------------------------------------
    # Jacobian Projective Coordinates: (X, Y, Z) -> (X/Z^2, Y/Z^3)
    # Eliminates modular inversions inside the scalar multiplication loop.
    # ------------------------------------------------------------------
    @staticmethod
    def _jacobian_double(X: int, Y: int, Z: int, p: int, a: int) -> tuple[int, int, int]:
        if Y == 0 or Z == 0:
            return (1, 1, 0)
        Y2 = (Y * Y) % p
        S = (4 * X * Y2) % p
        Z2 = (Z * Z) % p
        Z4 = (Z2 * Z2) % p
        M = (3 * X * X + a * Z4) % p
        X3 = (M * M - 2 * S) % p
        Y4 = (Y2 * Y2) % p
        Y3 = (M * (S - X3) - 8 * Y4) % p
        Z3 = (2 * Y * Z) % p
        return (X3, Y3, Z3)

    @staticmethod
    def _jacobian_add(
        X1: int, Y1: int, Z1: int, X2: int, Y2: int, Z2: int, p: int, a: int
    ) -> tuple[int, int, int]:
        if Z1 == 0:
            return (X2, Y2, Z2)
        if Z2 == 0:
            return (X1, Y1, Z1)
        Z1_2 = (Z1 * Z1) % p
        Z2_2 = (Z2 * Z2) % p
        U1 = (X1 * Z2_2) % p
        U2 = (X2 * Z1_2) % p
        S1 = (Y1 * Z2 * Z2_2) % p
        S2 = (Y2 * Z1 * Z1_2) % p
        if U1 == U2:
            if S1 != S2:
                return (1, 1, 0)
            return Point._jacobian_double(X1, Y1, Z1, p, a)
        H = (U2 - U1) % p
        R = (S2 - S1) % p
        H2 = (H * H) % p
        H3 = (H * H2) % p
        U1H2 = (U1 * H2) % p
        X3 = (R * R - H3 - 2 * U1H2) % p
        Y3 = (R * (U1H2 - X3) - S1 * H3) % p
        Z3 = (H * Z1 * Z2) % p
        return (X3, Y3, Z3)

    def _from_jacobian(self, X: int, Y: int, Z: int) -> Point:
        if Z == 0:
            return self.curve.infinity
        p = self.curve.p
        z_inv = mod_inv(Z, p)
        z_inv2 = (z_inv * z_inv) % p
        z_inv3 = (z_inv2 * z_inv) % p
        x = (X * z_inv2) % p
        y = (Y * z_inv3) % p
        return Point(self.curve, x, y, validate=False)

    def scalar_mul_jacobian(self, k: int) -> Point:
        """Fast scalar multiplication using Jacobian coordinates + Montgomery-style ladder."""
        if k < 0:
            return (-self).scalar_mul_jacobian(-k)
        if k == 0 or self.is_infinity:
            return self.curve.infinity
        assert self.x is not None and self.y is not None

        p = self.curve.p
        a = self.curve.a
        # Montgomery ladder in Jacobian coordinates for regular execution structure
        R0 = (1, 1, 0)
        R1 = (self.x, self.y, 1)
        for bit in bin(k)[2:]:
            if bit == "0":
                R1 = self._jacobian_add(*R0, *R1, p, a)
                R0 = self._jacobian_double(*R0, p, a)
            else:
                R0 = self._jacobian_add(*R0, *R1, p, a)
                R1 = self._jacobian_double(*R1, p, a)
        return self._from_jacobian(*R0)

    def scalar_mul_with_trace(self, k: int) -> tuple[Point, list[dict]]:
        """Educational double-and-add returning step-by-step intermediate points."""
        if k <= 0 or self.is_infinity:
            return self.curve.infinity, []
        bits = bin(k)[2:]
        trace: list[dict] = []
        current = self.curve.infinity
        for idx, bit in enumerate(bits):
            before = None if current.is_infinity else [current.x, current.y]
            current = current.double_affine()
            after_double = None if current.is_infinity else [current.x, current.y]
            added = False
            if bit == "1":
                current = current.add_affine(self)
                added = True
            after_step = None if current.is_infinity else [current.x, current.y]
            trace.append(
                {
                    "step": idx + 1,
                    "bit": bit,
                    "before": before,
                    "after_double": after_double,
                    "added_base": added,
                    "result": after_step,
                }
            )
        return current, trace

    def __add__(self, other: Point) -> Point:
        return self.add_affine(other)

    def __mul__(self, scalar: int) -> Point:
        if not isinstance(scalar, int):
            return NotImplemented
        return self.scalar_mul_jacobian(scalar)

    def __rmul__(self, scalar: int) -> Point:
        if not isinstance(scalar, int):
            return NotImplemented
        return self.scalar_mul_jacobian(scalar)


# ----------------------------------------------------------------------
# Standard Curves Registry (NIST / SEC2 + Educational Toy Curve)
# ----------------------------------------------------------------------

SECP256R1 = EllipticCurve(
    name="secp256r1",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    h=1,
    bit_size=256,
)

SECP256K1 = EllipticCurve(
    name="secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0x0,
    b=0x7,
    gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    h=1,
    bit_size=256,
)

SECP384R1 = EllipticCurve(
    name="secp384r1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
    b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    h=1,
    bit_size=384,
)

TOY_P97 = EllipticCurve(
    name="toy_p97",
    p=97,
    a=3,
    b=2,
    gx=2,
    gy=4,
    n=103,
    h=1,
    bit_size=7,
)

CURVES: dict[str, EllipticCurve] = {
    "secp256r1": SECP256R1,
    "P-256": SECP256R1,
    "secp256k1": SECP256K1,
    "secp384r1": SECP384R1,
    "P-384": SECP384R1,
    "toy_p97": TOY_P97,
}


def get_curve(name: str) -> EllipticCurve:
    if name not in CURVES:
        available = ", ".join(sorted(CURVES.keys()))
        raise ValueError(f"Unknown curve '{name}'. Available: {available}")
    return CURVES[name]
