"""Machine-checked proofs (Z3, bit-vector / integer arithmetic) of the
arithmetic lemmas the relay's correctness depends on.  Each lemma is proved by
showing its negation unsatisfiable, for ALL inputs (not sampled).

JS semantics modelled: `x >>> 0` and `(a - b) >>> 0` on 32-bit sequence numbers
are BV32 arithmetic; `|0` is the signed BV32 view.
"""
import sys
from z3 import *

failed = []
def prove(name, claim, *assumptions):
    s = Solver()
    s.set("timeout", 60000)
    s.add(*assumptions)
    s.add(Not(claim))
    r = s.check()
    ok = r == unsat
    print(f"  [{'PROVED' if ok else 'FAILED'}] {name}")
    if not ok:
        failed.append(name)
        if r == sat: print("     counterexample:", s.model())

H = BitVecVal(0x7FFFFFFF, 32)
def lt(a, b):                       # relay.js seqLessThan
    return UGT(a - b, H)

a, b, c, d = BitVecs("a b c d", 32)
print("Sequence-number arithmetic (relay.js seqLessThan / seqDiff)")
prove("seqLessThan irreflexive", Not(lt(a, a)))
prove("seqLessThan antisymmetric except exactly 2^31 apart",
      Implies(And(lt(a, b), lt(b, a)), a - b == BitVecVal(0x80000000, 32)))
prove("seqLessThan total on distinct points not 2^31 apart",
      Implies(And(a != b, a - b != BitVecVal(0x80000000, 32)), Xor(lt(a, b), lt(b, a))))
prove("seqLessThan(a, a+d) for every forward distance 1 <= d < 2^31 (holds across wrap)",
      lt(a, a + d), UGE(d, 1), ULT(d, BitVecVal(0x80000000, 32)))
prove("seqLessThan(a+d, a) is false for 0 <= d < 2^31",
      Not(lt(a + d, a)), ULT(d, BitVecVal(0x80000000, 32)))

print("TCPRetransmissionQueue.acknowledge classification")
una, nxt, ack = BitVecs("una nxt ack", 32)
adv, out = ack - una, nxt - una
HALF = BitVecVal(0x80000000, 32)
def status(adv, out):
    return If(adv == 0, 0, If(UGE(adv, HALF), 1, If(UGT(adv, out), 2, 3)))  # dup, stale, future, advanced
LIM = ULT(out, HALF)  # assumption A1: bytes in flight < 2^31 (relay caps in-flight by the <=65535 window)
prove("status 'advanced' <=> ack in (sndUna, sndNxt] modulo 2^32  (given in-flight < 2^31)",
      (status(adv, out) == 3) == And(ack != una, ULE(ack - una, nxt - una)), LIM)
prove("an ACK in (sndUna, sndNxt] is never misclassified stale/future (given in-flight < 2^31)",
      Implies(And(ack != una, ULE(adv, out)), status(adv, out) == 3), LIM)
prove("advancing by `advance` leaves outstanding' = outstanding - advance (no underflow)",
      (nxt - ack) == out - adv, ULE(adv, out))
prove("track: outstanding' = outstanding + len modulo 2^32",
      (nxt + c) - una == out + c)

print("Out-of-order buffer offsets (tcp_utils.js)")
e, seq1, seq2 = BitVecs("e s1 s2", 32)
o1, o2 = BitVecs("o1 o2", 32)
BOUND = 1 << 20   # offsets are bounded by the receive window (<= 65535) plus a segment length
bnd = lambda o: And(o >= -BOUND, o <= BOUND)
prove("signed-view comparator (a-e)|0 recovers the true offset for |offset| <= 2^20, across wrap",
      ((e + o1) - e) == o1, bnd(o1))   # BV32 identity: the |0 view equals o1 as a signed value
prove("sort comparator ((a-e)|0)-((b-e)|0) has the sign of the true offset difference (no overflow)",
      And(Implies(o1 < o2, SignExt(0, (e + o1) - e) < SignExt(0, (e + o2) - e)),
          Implies(o1 > o2, SignExt(0, (e + o1) - e) > SignExt(0, (e + o2) - e))), bnd(o1), bnd(o2))
prove("unsigned offset (seq - vmSeq)>>>0 equals the true offset for 0 <= offset < 2^20",
      ((e + o1) - e) == o1, o1 >= 0, o1 < BOUND)
prove("a range already passed (offset in [-2^20,0)) maps to >= 2^32-2^20, i.e. sorts after live ranges",
      UGE((e + o1) - e, BitVecVal(0x100000000 - BOUND, 32)), o1 < 0, o1 >= -BOUND)

print("Internet checksum (packet_utils.js); sums are JS doubles, exact below 2^53, so modelled as unbounded integers")
s = Int("s")
LIM53 = 2**53
def step(x): return If(x > 0xffff, (x % 65536) + (x / 65536), x)   # (sum & 0xffff) + floor(sum / 0x10000)
def iter_(x, k):
    for _ in range(k): x = step(x)
    return x
prove("fold step preserves the value modulo 65535 (end-around carry)",
      step(s) % 65535 == s % 65535, s >= 0, s < LIM53)
prove("fold loop terminates: 5 iterations suffice for any sum < 2^53 (result <= 0xffff)",
      iter_(s, 5) <= 0xffff, s >= 0, s < LIM53)
prove("fold never maps a positive sum to 0 (matches the RFC 1071 representation)",
      iter_(s, 5) > 0, s > 0, s < LIM53)
x = Int("x")
swap = lambda v: (v % 256) * 256 + v / 256
prove("byte-swap of a 16-bit value is multiplication by 256 modulo 65535 (RFC 1071 2(B) byte-order independence)",
      (swap(x) - 256 * x) % 65535 == 0, x >= 0, x <= 0xffff)
b0, b1, b2, b3 = Ints("b0 b1 b2 b3")
byte = lambda v: And(v >= 0, v <= 255)
w = b0 + 256 * b1 + 65536 * b2 + 16777216 * b3        # little-endian Uint32 view of 4 bytes
native = (w % 65536) + (w / 65536)
big = (b0 * 256 + b1) + (b2 * 256 + b3)                # the same bytes as two big-endian 16-bit words
prove("32-bit native-word path: native sum == 256 * big-endian sum (mod 65535), so one final swap is exact",
      (native - 256 * big) % 65535 == 0, byte(b0), byte(b1), byte(b2), byte(b3))
S, cks = Ints("S cks")
prove("transportChecksum cancels the stored checksum: S + (0xffff - c) == S - c  (mod 65535)",
      ((S + (0xffff - cks)) - (S - cks)) % 65535 == 0, cks >= 0, cks <= 0xffff)
prove("accumulators cannot overflow doubles: any 65535-byte buffer sums to < 2^53",
      65535 * 255 * 256 + 65535 * 255 < LIM53)

print("TCPPacer burst controller: inductive invariant")
burst, acked, init, mx, newburst, newacked, cwnd, ab = Ints("burst acked init mx nb na cwnd ab")
inv = lambda bu, ac: And(init <= bu, bu <= mx, ac >= 0)
base = [init >= 1, mx >= init]
# noteAck (adaptive)
thr = If(cwnd < 1, 1, cwnd)
acked2 = acked + ab
grow = And(acked2 >= thr, burst < mx)
nb = If(grow, burst + 1, burst); na = If(grow, acked2 - thr, acked2)
prove("noteAck preserves init <= burst <= max and acked >= 0",
      inv(nb, na), inv(burst, acked), ab > 0, *base)
# noteLoss: burst' = max(init, floor(burst/2))
half = burst / 2   # Z3 integer division (floor for non-negative)
nb2 = If(init > half, init, half)
prove("noteLoss preserves init <= burst <= max (and never grows burst)",
      And(inv(nb2, 0), nb2 <= burst), inv(burst, acked), *base)

print("parseTCPOptions: memory safety and termination (ranges as integers)")
start, end, plen, off, kind, ln = Ints("start end plen off kind ln")
pre = And(0 <= start, start <= end, end <= plen)
loop_inv = And(start <= off, off < end)
prove("kind byte read at off is in bounds", And(0 <= off, off < plen), pre, loop_inv)
guard = off + 1 < end
prove("length byte read at off+1 is in bounds under the guard", And(0 <= off + 1, off + 1 < plen), pre, loop_inv, guard)
valid = And(ln >= 2, off + ln <= end)
prove("MSS (len 4) payload reads off+2,off+3 stay below end", And(off + 3 < end), pre, loop_inv, guard, valid, ln == 4)
prove("window-scale (len 3) payload read off+2 stays below end", And(off + 2 < end), pre, loop_inv, guard, valid, ln == 3)
prove("every iteration strictly advances off and keeps off <= end (termination, no overrun)",
      And(off + ln > off, off + ln <= end), pre, loop_inv, guard, valid)
prove("NOP iteration advances by one (termination)", And(off + 1 > off, off + 1 <= end), pre, loop_inv)

print("RFC 6298 RTO bounds (tcp_retransmission.js sampleRtt)")
srtt, rttvar, mn, mxr, cur = Reals("srtt rttvar mn mxr cur")
raw = ToInt(srtt + If(4 * rttvar > 1, 4 * rttvar, 1)) + 1   # >= ceil(...)
rto = If(mxr < If(mn > raw, mn, raw), mxr, If(mn > raw, mn, raw))
prove("rto always lies in [minRto, maxRto] when minRto <= maxRto", And(rto >= mn, rto <= mxr), 0 < mn, mn <= mxr)
prove("backoff min(cur*2, max) never exceeds max and never decreases cur (cur <= max)",
      And(If(cur * 2 < mxr, cur * 2, mxr) <= mxr, If(cur * 2 < mxr, cur * 2, mxr) >= cur), 0 < cur, cur <= mxr)

print()
if failed:
    print("FAILED:", failed); sys.exit(1)
print("all lemmas proved")
