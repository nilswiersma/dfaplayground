from submod.aes.aes import AES, matrix2bytes

k = bytes.fromhex("2b7e1516 28aed2a6 abf71588 09cf4f3c")
i = bytes.fromhex("6bc1bee2 2e409f96 e93d7e11 7393172a")

ctx = AES(k[::-1])
c   = ctx.encrypt_block(i[::-1])[::-1]
iks = [b''.join(map(lambda x: bytes(x), ik)) for ik in ctx._key_matrices]


print(f'k: {k.hex()}')
for ik in iks:
	print(f'   {ik.hex()}')
print(f'i: {i.hex()}')
print(f'c: {c.hex()}')
print(f'')
# print(f'c: {hex(int.from_bytes(c, "big"))}')
# print(f'c: {hex(int.from_bytes(c, "little"))}')