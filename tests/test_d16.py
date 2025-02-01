from delta16 import Delta16
from delta16.d16 import opcode, opmask
from os import path


def relpath(f):
    return path.join(path.dirname(__file__), f)


def test_encode():
    assert Delta16._encode_op_inner('END') == bytes([opcode['END']])
    assert Delta16._encode_op_inner('CPY', 3) == bytes([opcode['CPY'] | 3])
    assert Delta16._encode_op_inner('CPY', 255) == bytes([opcode['CPY'] | opmask['CPY'], 255 - opmask['CPY']])
    assert Delta16._encode_op_inner('CPY', 1024) == bytes([opcode['CPY'], 0, 4])

    assert Delta16._encode_op_inner('MOV', 1) == bytes([opcode['MOV'] | 1])
#    assert Delta16._encode_op('MOV', 32) == bytes([opcode['MOV'] | 15, opcode['MOV'] | 15, opcode['MOV'] | 2])
    assert Delta16._encode_op_inner('SKP', -1) == bytes([opcode['SKP'], 0xff, 0xff])
    assert Delta16._encode_op_inner('INS', 3, bytes([1,2,3])) == bytes([opcode['INS'] | 3, 1, 2, 3])


def test_decode():
    assert Delta16._decode_op(bytearray([opcode['END']])) == ('END', 0)
    assert Delta16._decode_op(bytearray([opcode['MOV'] | 1])) == ('MOV', 1)
    assert Delta16._decode_op(bytearray([opcode['SKP'], 0xff, 0xff])) == ('SKP', 65535)
    assert Delta16._decode_op(bytearray([opcode['INS'] | 3, 1, 2, 3])) == ('INS', 3)


def test_nil():
    assert len(Delta16(b'').encode(b'')) == 13


def test_identity():
    ref = b'the quick brown fox jumps over the lazy dog'
    s = Delta16(ref).encode(ref, chunk_size=8)
    assert s[0:2] == bytes([0x16, 0x0d])
    assert s[2:4] == bytes([0, 0])      # src offset
    assert s[4:6] == bytes([len(ref), 0])
    assert s[6:8] == s[-2:]           # src and dst checksums
    assert s[8:10] == bytes([0, 0])     # dst offset
    assert s[10:-2] == bytes([opcode['CPY']|len(ref), 0])
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
    tgt = b'jumped over was the lazy dog by the quick brown f\x11\x00'
    #                       ^^^^^^^^^^^^
    #                                       ^^^^^^^^^^^^^^^^^^^^^^^^^

    # as written, the index mapping relocates the pointer
    s = Delta16(ref).encode(tgt, chunk_size=8)
    assert opcode['MOV'] | 1 in s
    assert Delta16(ref).decode(s) == tgt
    # if we shift tgt with a leading space the pointer is no longer relocatable
    assert (opcode['MOV'] | 1) not in Delta16(ref).encode(b' ' + tgt, chunk_size=8)


def test_reloc_addr():
    ref = b'the quick brown f\x20\x10 jumps over the lazy dog'  # start offset length
    tgt = b'jumped over was the lazy dog by the quick brown f\x11\x10'
    s = Delta16(ref, 0x1000).encode(tgt, chunk_size=8)
    assert opcode['MOV'] | 1 in s[10:-2]
    assert Delta16(ref, 0x1000).decode(s) == tgt
    # based at addr=0 the relocation no longer applies
    assert (opcode['MOV'] | 1) not in Delta16(ref).encode(tgt)[10:-2]


def test_rom():
    tgt = open(relpath('ucs.rom'), 'rb').read()
    ref = open(relpath('uc.rom'), 'rb').read()
    delta = Delta16(ref, 0x8000).encode(tgt)
    assert tgt == Delta16(ref, 0x8000).decode(delta)
    assert len(delta) == 2083
