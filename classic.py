from submod.aes.aes import AES, matrix2bytes
from submod.JeanGrey.phoenixAES import phoenixAES
import random

def single_bit_flip(s):
    i = random.choice(range(4))
    j = random.choice(range(4))
    bit = random.choice(range(8))
    s[i][j] = s[i][j] ^ (1<<bit)

def single_byte_corruption(s):
    i = random.choice(range(4))
    j = random.choice(range(4))
    s[i][j] = random.randint(0, 255)

def single_col_corruption(s):
    i = random.choice(range(4))
    s[i] = [random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)]

def random_multi_bit_flip(s):
    for _ in range(4):
        i = random.choice(range(4))
        j = random.choice(range(4))
        bit = random.choice(range(8))
        s[i][j] = s[i][j] ^ (1<<bit)

def single_byte_multi_bit_flip(s):
    i = random.choice(range(4))
    j = random.choice(range(4))
    for _ in range(4):
        bit = random.choice(range(8))
        s[i][j] = s[i][j] ^ (1<<bit)

def double_byte_multi_bit_flip(s):
    for _ in range(2):
        i = random.choice(range(4))
        j = random.choice(range(4))
        for _ in range(4):
            bit = random.choice(range(8))
            s[i][j] = s[i][j] ^ (1<<bit)

def triple_byte_multi_bit_flip(s):
    for _ in range(3):
        i = random.choice(range(4))
        j = random.choice(range(4))
        for _ in range(4):
            bit = random.choice(range(8))
            s[i][j] = s[i][j] ^ (1<<bit)

intermediates = [
    # 'input',
    # 'ark0',
    # 'sb1',
    # 'sr1',
    # 'mc1',
    # 'ark1',
    # 'sb2',
    # 'sr2',
    # 'mc2',
    # 'ark2',
    # 'sb3',
    # 'sr3',
    # 'mc3',
    # 'ark3',
    # 'sb4',
    # 'sr4',
    # 'mc4',
    # 'ark4',
    # 'sb5',
    # 'sr5',
    # 'mc5',
    # 'ark5',
    # 'sb6',
    # 'sr6',
    # 'mc6',
    # 'ark6',
    # 'sb7',
    # 'sr7',
    # 'mc7',
    # 'ark7',
    # 'sb8',
    # 'sr8',
    'mc8',
    'ark8',
    'sb9',
    'sr9',
    # 'mc9',
    # 'ark9',
    # 'sb10',
    # 'sr10',
    # 'ark10',
    ]

key        = b'SiDeChaNneLMarVl'
message    = b'sUpErSEcREtmESsG'
ctx = AES(bytes(key))
ciphertext = ctx.encrypt_block(bytes(message))
iks        = [b''.join(map(lambda x: bytes(x), ik)) for ik in ctx._key_matrices]

print(f'key        : {key.hex()}')
print(f'message    : {message.hex()}')
print(f'ciphertext : {ciphertext.hex()}')
ctr = 0
for ik in iks:
    print(f'ik{ctr:02}       : {ik.hex()}')
    ctr += 1

print('--encrypt--')
for intermediate in intermediates:
    faulted = []

    for _ in range(50):
        faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_bit_flip))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_byte_corruption))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_col_corruption))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_byte_multi_bit_flip))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=double_byte_multi_bit_flip))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=triple_byte_multi_bit_flip))
        # print(f'faulted    : {faulted[-1].hex()}')

    recovered, idx = phoenixAES.crack_bytes(faulted, ciphertext, verbose=0, encrypt=True)
    if recovered:
        print(f'recovered  : {recovered.hex()} ({idx}, {intermediate})')

# print('--decrypt--')
# for intermediate in intermediates:
#     faulted = []

#     for _ in range(50):
#         faulted.append(ctx.decrypt_block(bytes(ciphertext), glitch_at=intermediate))
#         # print(f'faulted    : {faulted[-1].hex()}')

#     recovered, idx = phoenixAES.crack_bytes(faulted, message, verbose=0, encrypt=False)
#     if recovered:
#         print(f'recovered  : {recovered.hex()} ({idx}, {intermediate})')