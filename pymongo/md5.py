from binascii import unhexlify

SINES = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
    0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
    0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
    0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
    0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039,
    0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
    0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
    0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

BIT_32 = 2 ** 32
BIT_64 = 2 ** 64
CHUNK_SIZE_BITS = 512


def left_circular_shift(k, bits):
    bits = bits % 32
    k = k % BIT_32
    upper = (k << bits) % BIT_32
    return upper | (k >> (32 - (bits)))


def block_divide(block, chunks):
    result = []
    size = len(block) // chunks
    for i in range(0, chunks):
        result.append(
            int.from_bytes(block[i * size:(i + 1) * size], byteorder="little")
        )
    return result


def aux_f(x, y, z):
    return (x & y) | ((~x) & z)


def aux_g(x, y, z):
    return (x & z) | (y & (~z))


def aux_h(x, y, z):
    return x ^ y ^ z


def aux_i(x, y, z):
    return y ^ (x | (~z))


def aux_ff(a, b, c, d, M, s, t):
    return b + left_circular_shift((a + aux_f(b, c, d) + M + t), s)


def aux_gg(a, b, c, d, M, s, t):
    return b + left_circular_shift((a + aux_g(b, c, d) + M + t), s)


def aux_hh(a, b, c, d, M, s, t):
    return b + left_circular_shift((a + aux_h(b, c, d) + M + t), s)


def aux_ii(a, b, c, d, M, s, t):
    return b + left_circular_shift((a + aux_i(b, c, d) + M + t), s)


def format_to_hexadecimal(num):
    bighex = "{0:08x}".format(num)
    binver = unhexlify(bighex)
    return "{0:08x}".format(int.from_bytes(binver, byteorder='little'))


def get_bit_length(bitstring):
    return len(bitstring) * 8


def md5sum(msg):
    msg = msg.encode()
    len_msg = get_bit_length(msg) % BIT_64
    msg += b'\x80'
    zero_padding = (448 - (len_msg + 8) % CHUNK_SIZE_BITS) % CHUNK_SIZE_BITS
    zero_padding //= 8
    msg += b'\x00' * zero_padding + len_msg.to_bytes(8, byteorder='little')
    len_msg = get_bit_length(msg)
    iterations = len_msg // CHUNK_SIZE_BITS

    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    for i in range(0, iterations):
        var_a = A
        var_b = B
        var_c = C
        var_d = D

        block = msg[i * 64:(i + 1) * 64]
        M = block_divide(block, 16)

        var_a = aux_ff(var_a, var_b, var_c, var_d, M[0], 7, SINES[0])
        var_d = aux_ff(var_d, var_a, var_b, var_c, M[1], 12, SINES[1])
        var_c = aux_ff(var_c, var_d, var_a, var_b, M[2], 17, SINES[2])
        var_b = aux_ff(var_b, var_c, var_d, var_a, M[3], 22, SINES[3])
        var_a = aux_ff(var_a, var_b, var_c, var_d, M[4], 7, SINES[4])
        var_d = aux_ff(var_d, var_a, var_b, var_c, M[5], 12, SINES[5])
        var_c = aux_ff(var_c, var_d, var_a, var_b, M[6], 17, SINES[6])
        var_b = aux_ff(var_b, var_c, var_d, var_a, M[7], 22, SINES[7])
        var_a = aux_ff(var_a, var_b, var_c, var_d, M[8], 7, SINES[8])
        var_d = aux_ff(var_d, var_a, var_b, var_c, M[9], 12, SINES[9])
        var_c = aux_ff(var_c, var_d, var_a, var_b, M[10], 17, SINES[10])
        var_b = aux_ff(var_b, var_c, var_d, var_a, M[11], 22, SINES[11])
        var_a = aux_ff(var_a, var_b, var_c, var_d, M[12], 7, SINES[12])
        var_d = aux_ff(var_d, var_a, var_b, var_c, M[13], 12, SINES[13])
        var_c = aux_ff(var_c, var_d, var_a, var_b, M[14], 17, SINES[14])
        var_b = aux_ff(var_b, var_c, var_d, var_a, M[15], 22, SINES[15])

        var_a = aux_gg(var_a, var_b, var_c, var_d, M[1], 5, SINES[16])
        var_d = aux_gg(var_d, var_a, var_b, var_c, M[6], 9, SINES[17])
        var_c = aux_gg(var_c, var_d, var_a, var_b, M[11], 14, SINES[18])
        var_b = aux_gg(var_b, var_c, var_d, var_a, M[0], 20, SINES[19])
        var_a = aux_gg(var_a, var_b, var_c, var_d, M[5], 5, SINES[20])
        var_d = aux_gg(var_d, var_a, var_b, var_c, M[10], 9, SINES[21])
        var_c = aux_gg(var_c, var_d, var_a, var_b, M[15], 14, SINES[22])
        var_b = aux_gg(var_b, var_c, var_d, var_a, M[4], 20, SINES[23])
        var_a = aux_gg(var_a, var_b, var_c, var_d, M[9], 5, SINES[24])
        var_d = aux_gg(var_d, var_a, var_b, var_c, M[14], 9, SINES[25])
        var_c = aux_gg(var_c, var_d, var_a, var_b, M[3], 14, SINES[26])
        var_b = aux_gg(var_b, var_c, var_d, var_a, M[8], 20, SINES[27])
        var_a = aux_gg(var_a, var_b, var_c, var_d, M[13], 5, SINES[28])
        var_d = aux_gg(var_d, var_a, var_b, var_c, M[2], 9, SINES[29])
        var_c = aux_gg(var_c, var_d, var_a, var_b, M[7], 14, SINES[30])
        var_b = aux_gg(var_b, var_c, var_d, var_a, M[12], 20, SINES[31])

        var_a = aux_hh(var_a, var_b, var_c, var_d, M[5], 4, SINES[32])
        var_d = aux_hh(var_d, var_a, var_b, var_c, M[8], 11, SINES[33])
        var_c = aux_hh(var_c, var_d, var_a, var_b, M[11], 16, SINES[34])
        var_b = aux_hh(var_b, var_c, var_d, var_a, M[14], 23, SINES[35])
        var_a = aux_hh(var_a, var_b, var_c, var_d, M[1], 4, SINES[36])
        var_d = aux_hh(var_d, var_a, var_b, var_c, M[4], 11, SINES[37])
        var_c = aux_hh(var_c, var_d, var_a, var_b, M[7], 16, SINES[38])
        var_b = aux_hh(var_b, var_c, var_d, var_a, M[10], 23, SINES[39])
        var_a = aux_hh(var_a, var_b, var_c, var_d, M[13], 4, SINES[40])
        var_d = aux_hh(var_d, var_a, var_b, var_c, M[0], 11, SINES[41])
        var_c = aux_hh(var_c, var_d, var_a, var_b, M[3], 16, SINES[42])
        var_b = aux_hh(var_b, var_c, var_d, var_a, M[6], 23, SINES[43])
        var_a = aux_hh(var_a, var_b, var_c, var_d, M[9], 4, SINES[44])
        var_d = aux_hh(var_d, var_a, var_b, var_c, M[12], 11, SINES[45])
        var_c = aux_hh(var_c, var_d, var_a, var_b, M[15], 16, SINES[46])
        var_b = aux_hh(var_b, var_c, var_d, var_a, M[2], 23, SINES[47])

        var_a = aux_ii(var_a, var_b, var_c, var_d, M[0], 6, SINES[48])
        var_d = aux_ii(var_d, var_a, var_b, var_c, M[7], 10, SINES[49])
        var_c = aux_ii(var_c, var_d, var_a, var_b, M[14], 15, SINES[50])
        var_b = aux_ii(var_b, var_c, var_d, var_a, M[5], 21, SINES[51])
        var_a = aux_ii(var_a, var_b, var_c, var_d, M[12], 6, SINES[52])
        var_d = aux_ii(var_d, var_a, var_b, var_c, M[3], 10, SINES[53])
        var_c = aux_ii(var_c, var_d, var_a, var_b, M[10], 15, SINES[54])
        var_b = aux_ii(var_b, var_c, var_d, var_a, M[1], 21, SINES[55])
        var_a = aux_ii(var_a, var_b, var_c, var_d, M[8], 6, SINES[56])
        var_d = aux_ii(var_d, var_a, var_b, var_c, M[15], 10, SINES[57])
        var_c = aux_ii(var_c, var_d, var_a, var_b, M[6], 15, SINES[58])
        var_b = aux_ii(var_b, var_c, var_d, var_a, M[13], 21, SINES[59])
        var_a = aux_ii(var_a, var_b, var_c, var_d, M[4], 6, SINES[60])
        var_d = aux_ii(var_d, var_a, var_b, var_c, M[11], 10, SINES[61])
        var_c = aux_ii(var_c, var_d, var_a, var_b, M[2], 15, SINES[62])
        var_b = aux_ii(var_b, var_c, var_d, var_a, M[9], 21, SINES[63])

        A = (A + var_a) % BIT_32
        B = (B + var_b) % BIT_32
        C = (C + var_c) % BIT_32
        D = (D + var_d) % BIT_32

    return format_to_hexadecimal(A) + \
        format_to_hexadecimal(B) + \
        format_to_hexadecimal(C) + \
        format_to_hexadecimal(D)
