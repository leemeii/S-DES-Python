from collections import defaultdict


# 置换表按从左到右、从 1 开始的位置编号，参数采用作业 PDF。
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INVERSE = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)
S1 = ((1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2))
# 第二个 S 盒使用 PDF 修改后的数值。
S2 = ((0, 1, 2, 3), (2, 3, 1, 0), (3, 0, 1, 2), (2, 1, 0, 3))


def parse_bits(value, width, name="输入"):
    value = value.strip()
    if len(value) != width or any(bit not in "01" for bit in value):
        raise ValueError(f"{name}必须是 {width} 位二进制，只能包含 0 和 1。")
    return int(value, 2)


def check_range(value, width, name):
    if type(value) is not int or not 0 <= value < 1 << width:
        raise ValueError(f"{name}必须是 0 到 {(1 << width) - 1} 之间的整数。")


def permute(value, width, table):
    # 按表提取输入位，并依次拼接为输出，兼容扩展和压缩置换。
    result = 0
    for position in table:
        result = result << 1 | (value >> (width - position) & 1)
    return result


def rotate_half(value, shift):
    # 将移出的高位补到低位，掩码 31 将结果限制为 5 位。
    return ((value << shift) | (value >> (5 - shift))) & 31


def subkeys(key):
    check_range(key, 10, "密钥")
    mixed = permute(key, 10, P10)
    left, right = mixed >> 5, mixed & 31
    # 按 PDF 公式字面取法：两次移位都从 P10 后的原始半部分开始。
    # K2 累计左移 2 位；与常见的累计 3 位规则不同，跨组互测前需统一。
    return tuple(
        permute(rotate_half(left, shift) << 5 | rotate_half(right, shift), 10, P8)
        for shift in (1, 2)
    )


def substitute(value, box):
    # 4 位输入的首尾两位确定行，中间两位确定列。
    row = ((value & 8) >> 2) | (value & 1)
    column = (value >> 1) & 3
    return box[row][column]


def round_function(right, key):
    # 右半部先扩展并与子密钥异或，再经两个 S 盒压缩，最后做 P4 置换。
    value = permute(right, 4, EP) ^ key
    replaced = substitute(value >> 4, S1) << 2 | substitute(value & 15, S2)
    return permute(replaced, 4, P4)


def transform(block, keys):
    check_range(block, 8, "数据分组")
    value = permute(block, 8, IP)
    left, right = value >> 4, value & 15
    left ^= round_function(right, keys[0])
    # 仅在两轮之间交换左右半部，第二轮之后直接进行逆初始置换。
    left, right = right, left
    left ^= round_function(right, keys[1])
    return permute(left << 4 | right, 8, IP_INVERSE)


def encrypt(block, key):
    return transform(block, subkeys(key))


def decrypt(block, key):
    # Feistel 结构允许复用加密流程，只需反转两个子密钥的使用顺序。
    return transform(block, subkeys(key)[::-1])


def encrypt_text(text, key):
    try:
        data = text.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("字符串模式只支持 ASCII 字符，不支持中文或表情。") from None
    keys = subkeys(key)
    # 每个 ASCII 字符独立加密为一个字节，十六进制显示可保留不可打印的密文。
    return bytes(transform(value, keys) for value in data).hex(" ").upper()


def decrypt_text(ciphertext, key):
    try:
        data = bytes.fromhex(ciphertext)
    except ValueError:
        raise ValueError("密文必须是完整的十六进制字节，例如 A0 12 FF。") from None
    keys = subkeys(key)[::-1]
    result = bytes(transform(value, keys) for value in data)
    try:
        return result.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("解密结果含非 ASCII 字节，请检查密钥和密文。") from None


def parse_pairs(text):
    pairs = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2:
            raise ValueError(f"第 {number} 行需要一组明文和密文，中间用空格分隔。")
        pairs.append((parse_bits(fields[0], 8, "明文"), parse_bits(fields[1], 8, "密文")))
    if not pairs:
        raise ValueError("请至少输入一组已知明文和密文。")
    return pairs


def matches_key(pairs, key):
    keys = subkeys(key)
    # 候选密钥必须满足所有已知明密文对，遇到不匹配时提前结束检查。
    return all(transform(plain, keys) == cipher for plain, cipher in pairs)


def find_keys(pairs):
    if not pairs:
        raise ValueError("至少需要一组已知明文和密文。")
    for plain, cipher in pairs:
        check_range(plain, 8, "明文")
        check_range(cipher, 8, "密文")
    # 遍历完整的 10 位密钥空间，保留全部候选，包括无法区分的等效密钥。
    return [key for key in range(1024) if matches_key(pairs, key)]


def collision_groups(plain):
    check_range(plain, 8, "明文")
    groups = defaultdict(list)
    # 固定明文，按密文归组；同组中有多个密钥就说明发生了碰撞。
    for key in range(1024):
        groups[encrypt(plain, key)].append(key)
    return dict(sorted(groups.items()))
