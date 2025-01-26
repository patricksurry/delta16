import numpy as np
from collections import namedtuple


class IndexMapping(namedtuple('IndexMapping', ['start', 'offset', 'length'])):
    __slots__ = ()
    @property
    def empty(self):
        return not self.length

    def map(self, i: int):
        if self.start <= i < self.start + self.length:
            return i + self.offset
        else:
            return None

    @property
    def end(self):
        return self.start + self.length

    @property
    def map_start(self):
        return self.start + self.offset

    @property
    def map_end(self):
        return self.map_start + self.length


class RelocationTable:
    def __init__(self, entries: list[IndexMapping] = [], addr_start = 0, addr_offset = 0):
        self.entries = [
            IndexMapping(e.start + addr_start, e.offset + addr_offset, e.length)
            for e in entries
        ]

    def relocate(self, addr) -> int | None:
        a = None
        for e in self.entries:
            if a := e.map(addr):
                break
        return a


def pack16(n: int) -> bytes:
    assert 0 <= n < 1 << 16
    return bytes([n & 0xff, n >> 8])


def hexstring(d: bytes):
    return " ".join(f"{v:02x}" for v in d)


def addr16(xs: bytes):
    assert len(xs) >= 2
    return xs[0] | xs[1] << 8


def fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    for byte in data:
        sum1 += byte
        if sum1 >= 255:
            sum1 -= 255
        sum2 += sum1
        if sum2 >= 255:
            sum2 -= 255
    return (sum2 << 8) | sum1


def find_overlap(a: bytes, b: bytes, max_error_run=16) -> tuple[int, int]:
    """
    greedy match for longest overlap between a and b
    allowing up to max_error_run mismatching bytes
    return result as (offset, length)
    """
    max_n = min(len(a), len(b))
    err = 0
    n = 0
    while n < max_n and a[n] != b[n]:
        n += 1
    if n == max_n:
        return None
    start = n
    while n < max_n:
        if a[n] != b[n]:
            err += 1
        else:
            err = 0
        if err > max_error_run:
            n -= max_error_run
            break
        n += 1
    return (start, n-start)


def find_fragments(dst: bytes, ref: bytes, block_size=64) -> list[IndexMapping]:
    """
    find matching fragments betwen ref and dst, with at least block_size/2 overlap
    returns a list of matches
    """
    if not (dst and ref):
        return []

    min_size = block_size
    min_overlap = min(2, block_size // 2)
    block_size = min(block_size, len(ref))

    r = np.frombuffer(ref, dtype='uint8')

    # make a rectangular array of shifted ref strings
    # so that we can match a chunk of ref at all possible spots
    # e.g. given "abcdefghij" of length 10 and block size 4
    # we'd make an array of shape 10-4+1 = 7 x 4 and can
    # match a string like "dcfi" like so:
    #
    #    abcdefg  d  0001000
    #    bcdefgh  c  0100000
    #    cdefghi  f  0001000
    #    defghij  i  0000010
    #                -------
    #                0102010
    #       ^-----------^------- best match @ index 3
    #
    # Note this will miss partial matches at the start or end
    # of ref, e.g. "zabc" will score 0.  But we use this
    # to find an aligned block, and then extend the matching fragment
    # from there.

    # shape (n-block_size+1, block_size)
    cmp = np.stack([
        r[i:i-block_size+1 or None] for i in range(block_size)
    ]).T

    i = 0           # index to dst
    matches = []

    while i < len(dst):
        # take next chunk of dst
        chunk = np.frombuffer(dst[i:i+block_size], dtype='uint8')
        # compare it against all the substrings of ref, counting matches
        similarity = (chunk == cmp[:,:len(chunk)]).sum(axis=1)
        # find the offset with the biggest overlap
        j = int(similarity.argmax())    # index to ref
        # if we got at least 50% match, find the overlapping length
        match = None
        if similarity[j] > min_overlap:
            # allow the match to extend backward from the end of the last one
            # but not before the start of either string
            lookback = 0 if not matches else min(
                i - matches[-1].map_end,
                i,
                j
            )
            result = find_overlap(dst[i-lookback:], ref[j-lookback:], max_error_run=min_size//4)
            assert result
            (start, n) = result
            if n >= min_size:
                match = IndexMapping(j - lookback + start, i - j, n)

        if match:
            matches.append(match)
            i = match.map_end
        else:
            i += block_size

    return matches
