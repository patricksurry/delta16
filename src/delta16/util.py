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

    def __repr__(self):
        return f"[{self.start}:][:{self.length}] => [{self.start+self.offset}:...]"

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

    def __repr__(self):
        return '\n'.join(repr(e) for e in self.entries)

    @classmethod
    def identity(cls, size=0x10000):
        return cls([IndexMapping(0,0,size)])

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
    find (start, b) so that a[start:][:n] is mostly equal to b[start:][:n]
    with the end elements matching and at most max_error_run
    consecutive mismatching values.
    any initial mismatch is ignored
    """
    n = min(len(a), len(b))
    xs = np.frombuffer(a[:n], dtype='uint8')
    ys = np.frombuffer(b[:n], dtype='uint8')

    diff = np.where(xs != ys, 1, 0)
    matched = np.flatnonzero(diff == 0)
    if len(matched):
        start, stop = matched[0], matched[-1]+1
    else:
        return (0, 0)
    # right shift and left pad with 0, e.g. [0] + diff[:-1]
    shifted = np.pad(diff[:-1], (1, 0))
    # tag the start of mismatched runs
    boundaries = np.flatnonzero(diff - shifted == 1)
    # do a cumulative sum of mismatches from right to left
    rcumerr = diff[::-1].cumsum()[::-1]
    # note the cume sums at the start of runs
    cumsizes = rcumerr[boundaries]
    # get run sizes by subtracting the next value
    sizes = cumsizes - np.pad(cumsizes[1:], (0, 1))
    # get indices of runs that are too long
    too_long = np.flatnonzero(sizes > max_error_run)
    stop = next((boundaries[k] for k in too_long if boundaries[k] >= start), stop)
    i, j = int(start), int(stop)
    assert a[i] == b[i] and a[j-1] == b[j-1]
    return (i, j-i)


def find_fragments(dst: bytes, src: bytes, block_size=64) -> list[IndexMapping]:
    """
    find matching fragments between dst and src, with at least block_size/2 overlap
    returns a list of matches in increasing (and non-overlapping) dst order
    """
    if not (dst and src):
        return []

    min_size = block_size
    min_overlap = max(2, block_size // 2)
    block_size = min(block_size, len(src))

    # make a rectangular array of shifted src strings
    # so that we can match a chunk of src at all possible spots
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
    # of src, e.g. "zabc" will score 0.  But we use this
    # to find an aligned block, and then extend the matching fragment
    # from there.

    # shape (n-block_size+1, block_size)
    a = np.frombuffer(src, dtype='uint8')
    cmp = np.stack([
        a[i:i-block_size+1 or None] for i in range(block_size)
    ]).T

    i_dst = 0
    matches = []

    while i_dst < len(dst):
        # take next chunk of dst
        chunk = np.frombuffer(dst[i_dst:i_dst+block_size], dtype='uint8')
        # compare it against all the substrings of src, counting matches
        similarity = (chunk == cmp[:,:len(chunk)]).sum(axis=1)
        # find the offset with the biggest overlap
        i_src = int(similarity.argmax())    # index to src
        # if we got at least 50% match, find the overlapping length
        match = None
        if similarity[i_src] >= min_overlap:
            # allow the match to extend backward from the end of the last one
            # but not before the start of either string
            lookback = 0 if not matches else min(
                i_dst - matches[-1].map_end,
                i_dst,
                i_src,
            )
            max_err = min_size//4
            while True:
                (start, n) = find_overlap(dst[i_dst - lookback:], src[i_src - lookback:], max_error_run=max_err)
                if start >= lookback or n >= min_size:
                    break
                lookback = max(0, lookback - start - n)

            if n >= min_size:
                match = IndexMapping(i_src - lookback + start, i_dst - i_src, n)

        if match:
            assert not matches or match.map_start >= matches[-1].map_end, matches + [match]
            matches.append(match)
            i_dst = match.map_end
        else:
            i_dst += block_size

    return matches
