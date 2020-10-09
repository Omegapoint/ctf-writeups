#!/usr/bin/env python3
#
# Solution to xor challenge from FOI CTF 2020 (20/20 CTF)
# By: Jakob Petersson https://github.com/JakobPetersson
#

from __future__ import annotations
from dataclasses import dataclass
from time import sleep

@dataclass
class BitStat:
    """Class for keeping track of bit value occurrences"""
    count_0: int = 0
    count_1: int = 0

    def add(self, bit_value_to_add) -> BitStat:
        """Creates new BitStatistics with value added"""
        if bit_value_to_add == 0:
            return BitStat(self.count_0 + 1, self.count_1)
        else:
            return BitStat(self.count_0, self.count_1 + 1)

    def most_probable_value(self) -> int:
        """Return the most probable value based on statistics"""
        if self.count_0 >= self.count_1:
            return 0
        else:
            return 1


class BitStatistics:
    bit_stats: [BitStat] = []

    @staticmethod
    def hex_string_to_bytearray(hex_string: str) -> bytearray:
        """Converts from hex string to bytearray"""
        return bytearray.fromhex(hex_string)

    @staticmethod
    def bytearray_to_byte_array(input: bytearray) -> [int]:
        """Converts from bytearray to array of bytes"""
        return list(map(lambda bit_stat: bit_stat, input))

    @staticmethod
    def byte_to_bit_array(byte: int) -> [int]:
        """Converts a byte to an array of bits"""
        return [int(i) for i in "{0:08b}".format(byte)]

    @staticmethod
    def bit_array_to_byte_array(bit_array: [int]) -> [int]:
        return [sum([byte[b] << b for b in range(0, 8)])
                for byte in zip(*(iter(bit_array),) * 8)
                ]

    def init_bit_stats(self, number_of_bits: int):
        """Initializes bit_stats to correct number of bits"""
        if len(self.bit_stats) == 0:
            self.bit_stats = [BitStat()] * number_of_bits

    def update_bit(self, bit_index: int, bit_value: int):
        """Updates statistics for a single bit with additional 1 or 0"""
        current_bit_stats = self.bit_stats[bit_index]
        self.bit_stats[bit_index] = current_bit_stats.add(bit_value)

    def handle_ciphertext(self, count: int, ciphertext: str):
        print(f"Handling ciphertext #{count}")
        ciphertext_byte_array = self.bytearray_to_byte_array(self.hex_string_to_bytearray(ciphertext))
        self.init_bit_stats(len(ciphertext_byte_array) * 8)

        # print(f"raw: {ciphertext}", end='')
        # print(f"in: {ciphertext_byte_array}")

        for byte_index, byte_value in enumerate(ciphertext_byte_array):
            bits = self.byte_to_bit_array(byte_value)
            for bit_in_byte_index, bit_value in enumerate(bits):
                bit_index = (byte_index * 8) + (7 - bit_in_byte_index)
                self.update_bit(bit_index, bit_value)

        self.print()

    def most_probable_bit_array(self) -> [int]:
        return list(map(lambda bit_stat: bit_stat.most_probable_value(), self.bit_stats))

    def most_probable_byte_array(self) -> [int]:
        return self.bit_array_to_byte_array(self.most_probable_bit_array())

    def most_probable_chr_array(self) -> [str]:
        return list(map(lambda byte: chr(byte), self.most_probable_byte_array()))

    def most_probable_string(self) -> str:
        return ''.join(self.most_probable_chr_array())

    def print(self):
        print(self.most_probable_string())


with open('ciphertexts.txt') as fp:
    """Read ciphertexts one by one"""
    bit_stats = BitStatistics()
    for cnt, line in enumerate(fp):
        bit_stats.handle_ciphertext(cnt, line)
        sleep(0.1)
