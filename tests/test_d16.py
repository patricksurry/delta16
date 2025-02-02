from delta16 import Delta16
from delta16.inst import Instruction
from os import path


def relpath(f):
    return path.join(path.dirname(__file__), f)


def test_nil():
    assert len(Delta16(b'').encode(b'')) == 13


def test_identity():
    ref = b'the quick brown fox'
    assert len(ref) <= Instruction.mask['CPY']  # string should be short enough for a one-byte CPY
    s = Delta16(ref).encode(ref, chunk_size=8)
    assert s[0:2] == bytes([0x16, 0x0d])
    assert s[2:4] == bytes([0, 0])      # src offset
    assert s[4:6] == bytes([len(ref), 0])
    assert s[6:8] == s[-2:]             # src and dst checksums
    assert s[8:10] == bytes([0, 0])     # dst offset
    assert s[10:-2] == bytes([Instruction.prefix['CPY']|len(ref), 0])
    assert len(s) == 14


def test_roundtrip():
    ref = b'the quick brown fox jumps over the lazy dog'
    tgt = b'jumps over the lazy dog does the quick brown fox'
    delta = Delta16(ref).encode(tgt, chunk_size=8)
    assert tgt == Delta16(ref).decode(delta)


def test_reloc():
    # \x20\x00 points to the h in 'the lazy dog'
    ref = b'the quick brown f\x20\x00 jumps over the lazy dog'  # start offset length
    #                                            ^^^^^^^^^^^^      31   -15     12
    #       ^^^^^^^^^^^^^^^^^^^^^^^^^                               0    32     19
    # \x11\x00 points to the same h in 'the lazy dog'
    # note f vs F before the relocation to prevent elision to CPM
    tgt = b'jumped over was the lazy dog by the quick brown F\x11\x00'
    #                       ^^^^^^^^^^^^
    #                                       ^^^^^^^^^^^^^^^^^^^^^^^^^

    # as written, the index mapping relocates the pointer
    s = Delta16(ref).encode(tgt, chunk_size=8)
    assert Instruction.prefix['MOV'] | 1 in s
    assert Delta16(ref).decode(s) == tgt
    # if we shift tgt with a leading space the pointer is no longer relocatable
    assert (Instruction.prefix['MOV'] | 1) not in Delta16(ref).encode(b' ' + tgt, chunk_size=8)


def test_reloc_addr():
    ref = b'the quick brown f\x20\x10 jumps over the lazy dog'  # start offset length
    tgt = b'jumped over was the lazy dog by the quick brown F\x11\x10'
    s = Delta16(ref, 0x1000).encode(tgt, chunk_size=8)
    assert Instruction.prefix['MOV'] | 1 in s[10:-2]
    assert Delta16(ref, 0x1000).decode(s) == tgt
    # based at addr=0 the relocation no longer applies
    assert (Instruction.prefix['MOV'] | 1) not in Delta16(ref).encode(tgt)[10:-2]


def test_rom():
    tgt = open(relpath('ucs.rom'), 'rb').read()
    ref = open(relpath('uc.rom'), 'rb').read()
    delta = Delta16(ref, 0x8000).encode(tgt)
    assert tgt == Delta16(ref, 0x8000).decode(delta)
    assert len(delta) == 1483       # w/ gzip compress => 1406
