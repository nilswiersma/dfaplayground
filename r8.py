from submod.aes.aes import AES, matrix2bytes
from submod.JeanGrey.phoenixAES import phoenixAES
import random, os
import faultmodels

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
    'sr8',

    # 'mc8',
    # 'ark8',
    # 'sb9',
    # 'sr9',
    
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
    print(f'--{intermediate}--')
    faulted = []
    for _ in range(40):
        faulted.append(os.urandom(16))
    for _ in range(2):
        faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=faultmodels.single_bit_flip))
        faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=faultmodels.single_byte_corruption))
        faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=faultmodels.single_col_corruption))
        faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=faultmodels.single_row_corruption))
        faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=faultmodels.single_byte_multi_bit_flip))
        faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=faultmodels.double_byte_multi_bit_flip))
        faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=faultmodels.triple_byte_multi_bit_flip))
        faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=faultmodels.single_bit_every_byte))
        # print(f'faulted    : {faulted[-1].hex()}')
    random.shuffle(faulted)
    roundkey, idx, candidates = phoenixAES.crack_bytes(faulted, ciphertext, verbose=0, encrypt=True)
    print(f"roundkey   : {''.join(['%02x' % x if x is not None else '..' for x in roundkey])} ({idx}, {intermediate}) {''.join(['%02x' % x if x is not None else '..' for x in roundkey]) == iks[-1].hex()}")
    if None in roundkey:
        roundkey, idx, candidates = phoenixAES.crack_bytes(
            phoenixAES.convert_r8faults_bytes(faulted, ciphertext), ciphertext, verbose=0, encrypt=True)
        print(f"roundkey   : {''.join(['%02x' % x if x is not None else '..' for x in roundkey])} ({idx}, {intermediate}) {''.join(['%02x' % x if x is not None else '..' for x in roundkey]) == iks[-1].hex()}")
