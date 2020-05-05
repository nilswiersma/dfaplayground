from submod.aes.aes import AES, matrix2bytes, xor_bytes, r_con, s_box, inv_s_box, reverse_expand_key
key        = b'SiDeChaNneLMarVl'
message    = b'sUpErSEcREtmESsG'
ctx = AES(bytes(key))
ciphertext = ctx.encrypt_block(bytes(message))
iks        = [b''.join(map(lambda x: bytes(x), ik)) for ik in ctx._key_matrices]

print(f'key        : {key.hex()}')
print(f'message    : {message.hex()}')
print(f'ciphertext : {ciphertext.hex()}')

ctr = 0
for ik in ctx._expand_key(key):
    print(f'ik{ctr:02}       : {b"".join(map(lambda x: bytes(x), ik)).hex()}')
    ctr += 1

ctr = 0
for ik in reverse_expand_key(iks[-1]):
    print(f'ik{ctr:02}       : {ik.hex()}')
    ctr += 1
