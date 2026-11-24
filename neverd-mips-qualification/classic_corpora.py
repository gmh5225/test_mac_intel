"""Deterministic MIPS III word sequences used by both timing protocols."""
import random


def varied_words():
    generator = random.Random(41598)
    immediate = (4, 5, 8, 9, 10, 11, 12, 13, 14, 32, 33, 36, 37, 40, 41)
    alu = (32, 33, 34, 35, 36, 37, 38, 39, 42, 43)
    for name, count in [('MIPS III varied', 2048), ('MIPS III mixed memory and exceptions', 768)]:
        words = []
        for i in range(count):
            rs, rt, rd = (generator.randrange(32) for _ in range(3))
            imm = generator.randrange(65536)
            fmt = i % 3 if name == 'MIPS III varied' else 2
            if fmt == 0:
                word = generator.choice(immediate) << 26 | rs << 21 | rt << 16 | imm
            elif fmt == 1:
                word = rs << 21 | rt << 16 | rd << 11 | generator.choice(alu)
            else:
                registers = rs << 21 | rt << 16
                word = generator.choice([35 << 26 | registers | imm,
                                         43 << 26 | registers | imm,
                                         25 << 26 | registers | imm,
                                         rd << 11 | 16, registers | (imm & 1023) << 6 | 52,
                                         (imm & 65535) << 6 | 12])
            words.append(word)
        yield name, ('mips3', words)
