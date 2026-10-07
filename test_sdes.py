import unittest

from sdes import collision_groups, decrypt, decrypt_text, encrypt, encrypt_text
from sdes import find_keys, parse_bits, parse_pairs, subkeys, transform


def reference_encrypt(plain, key):
    # 使用字符串逐位实现，不调用主程序的算法函数，用于独立核对位运算结果。
    def select(bits, indexes):
        return "".join(bits[index - 1] for index in indexes)

    def xor(left, right):
        return "".join(str(int(a) ^ int(b)) for a, b in zip(left, right))

    def lookup(bits, box):
        return f"{box[int(bits[0] + bits[3], 2)][int(bits[1:3], 2)]:02b}"

    def step(left, right, round_key):
        expanded = select(right, [4, 1, 2, 3, 2, 3, 4, 1])
        mixed = xor(expanded, round_key)
        a = lookup(mixed[:4], [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]])
        b = lookup(mixed[4:], [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]])
        return xor(left, select(a + b, [2, 4, 3, 1])), right

    mixed = select(f"{key:010b}", [3, 5, 2, 7, 4, 10, 1, 9, 8, 6])
    halves = [mixed[:5], mixed[5:]]
    keys = [select("".join(half[shift:] + half[:shift] for half in halves),
                   [6, 3, 7, 4, 8, 5, 10, 9]) for shift in [1, 2]]
    block = select(f"{plain:08b}", [2, 6, 3, 1, 4, 8, 5, 7])
    left, right = step(block[:4], block[4:], keys[0])
    left, right = step(right, left, keys[1])
    return int(select(left + right, [4, 1, 3, 5, 7, 2, 8, 6]), 2)


class SDESTests(unittest.TestCase):
    def test_key_schedule(self):
        self.assertEqual(subkeys(0), (0, 0))
        self.assertEqual(subkeys(1023), (255, 255))
        self.assertEqual(subkeys(int("1010000010", 2)), (int("10100100", 2), int("10010010", 2)))

    def test_all_blocks_and_keys(self):
        # 穷举检查可逆性，同时验证固定密钥下不会有两个明文产生相同密文。
        for key in range(1024):
            keys = subkeys(key)
            encrypted = [transform(plain, keys) for plain in range(256)]
            self.assertEqual(len(set(encrypted)), 256, f"key={key}")
            for plain, cipher in enumerate(encrypted):
                self.assertEqual(transform(cipher, keys[::-1]), plain, f"key={key}, plain={plain}")

    def test_independent_reference(self):
        # 可逆性本身不能证明符合约定，因此再用参考实现核对全部输入组合。
        for key in range(1024):
            keys = subkeys(key)
            for plain in range(256):
                self.assertEqual(transform(plain, keys), reference_encrypt(plain, key),
                                 f"key={key}, plain={plain}")

    def test_public_encrypt_decrypt(self):
        for key in (0, 1, 341, 642, 1023):
            for plain in (0, 1, 85, 170, 215, 255):
                self.assertEqual(decrypt(encrypt(plain, key), key), plain)

    def test_ascii(self):
        # 包含不可打印字符和前后空格，检查字符串处理是否丢失数据。
        texts = ["", "Hello, S-DES!", "  leading and trailing  ", "line1\nline2\t\x00", "".join(map(chr, range(128))) ]
        for key in (0, 642, 1023):
            for text in texts:
                cipher = encrypt_text(text, key)
                self.assertEqual(len(bytes.fromhex(cipher)), len(text))
                self.assertEqual(decrypt_text(cipher, key), text)

    def test_invalid_inputs(self):
        for value in ("", "010", "111111111", "01010102", "0101 0101"):
            with self.assertRaises(ValueError):
                parse_bits(value, 8)
        for value in ("0", "GG", "123", "0x01", "A A"):
            with self.assertRaises(ValueError):
                decrypt_text(value, 642)
        for text in ("中文", "é", "😀"):
            with self.assertRaises(ValueError):
                encrypt_text(text, 642)
        for key in (-1, 1024, "1010000010", True):
            with self.assertRaises(ValueError):
                encrypt(0, key)
        for block in (-1, 256, None):
            with self.assertRaises(ValueError):
                decrypt(block, 0)
        with self.assertRaises(ValueError):
            decrypt_text(f"{encrypt(128, 642):02X}", 642)

    def test_parse_pairs(self):
        self.assertEqual(parse_pairs("00000000 11111111\n\n00000001\t00000010"), [(0, 255), (1, 2)])
        for text in ("", "00000000", "00000000 11111111 extra", "x 11111111"):
            with self.assertRaises(ValueError):
                parse_pairs(text)

    def test_brute_force(self):
        key = 642
        pair = (0, reference_encrypt(0, key))
        expected = [candidate for candidate in range(1024) if reference_encrypt(0, candidate) == pair[1]]
        candidates = find_keys([pair])
        self.assertEqual(candidates, expected)
        self.assertIn(key, candidates)
        self.assertGreater(len(candidates), 1)
        pairs = [(plain, reference_encrypt(plain, key)) for plain in range(256)]
        # 当前移位规则存在等效密钥，即使给出全部明文的密文，也应保留两个候选。
        self.assertEqual(find_keys(pairs), [642, 898])
        self.assertEqual(subkeys(642), subkeys(898))
        self.assertEqual(find_keys([(0, 0), (0, 1)]), [])
        with self.assertRaises(ValueError):
            find_keys([])

    def test_equivalent_keys(self):
        # 256 对应原密钥从左数第 2 位，翻转该位不会改变当前规则生成的子密钥。
        self.assertEqual(len({subkeys(key) for key in range(1024)}), 512)
        for key in range(1024):
            self.assertEqual(subkeys(key), subkeys(key ^ 256))

    def test_collision_groups(self):
        for plain in (0, 85, 170, 255):
            groups = collision_groups(plain)
            self.assertEqual(sorted(key for keys in groups.values() for key in keys), list(range(1024)))
            self.assertLessEqual(len(groups), 256)
            self.assertTrue(any(len(keys) > 1 for keys in groups.values()))
            for cipher, keys in groups.items():
                self.assertTrue(all(reference_encrypt(plain, key) == cipher for key in keys))


if __name__ == "__main__":
    unittest.main(verbosity=2)
