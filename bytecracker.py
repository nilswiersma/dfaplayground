from submod.aes.aes import AES, matrix2bytes
from submod.JeanGrey.phoenixAES import phoenixAES
import random, os
import faultmodels
import tqdm


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

    # 'mc8',
    # 'ark8',
    'sb9',
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


faulted = []
for _ in range(10000):
    faulted.append(os.urandom(16))
for _ in range(2):
    faulted.append(ctx.encrypt_block(bytes(message), glitch_at='sb9', glitch=faultmodels.single_bit_flip))
for _ in range(3):
    faulted.append(ctx.encrypt_block(bytes(message), glitch_at='sb8', glitch=faultmodels.single_bit_flip))
    # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_byte_corruption))
    # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_col_corruption))
    # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_byte_multi_bit_flip))
    # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=double_byte_multi_bit_flip))
    # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=triple_byte_multi_bit_flip))
    # print(f'faulted    : {faulted[-1].hex()}')
random.shuffle(faulted)

cracker = phoenixAES.ByteCracker(ciphertext, encrypt=True, verbose=0)

# try treating as r9 faults
for faulty in faulted:
    new_sol = cracker.crack_bytes(faulty)
    if new_sol:# and [] not in cracker.solutions:
        exit = False
        print(f'result after {cracker.counter} good faulted analyzed')
        for key in cracker.key_solutions():
            print(phoenixAES.hexdot(key), phoenixAES.hexdot(key) == iks[-1].hex())
            if phoenixAES.hexdot(key) == iks[-1].hex():
                exit = True
        if exit:
            break

# for key in cracker.key_solutions():
#     print(phoenixAES.hexdot(key), phoenixAES.hexdot(key) == iks[-1].hex())

# r9 faults dont produce false positives
for idx in range(len(cracker.solutions)):
    cracker.recovered[idx] = [] != cracker.solutions[idx]
print(cracker.recovered)

# check for r8 faults
faulted2 = phoenixAES.convert_r8faults_bytes(faulted, ciphertext)
for faulty in tqdm.tqdm(faulted2):
    new_sol = cracker.crack_bytes(faulty)
    if new_sol:# and [] not in cracker.solutions:
        exit = False
        print(f'result after {cracker.counter} good faulted analyzed')
        for key in cracker.key_solutions():
            print(phoenixAES.hexdot(key), phoenixAES.hexdot(key) == iks[-1].hex())
            if phoenixAES.hexdot(key) == iks[-1].hex():
                exit = True
        if exit:
            break

# for key in cracker.key_solutions():
#     print(phoenixAES.hexdot(key), phoenixAES.hexdot(key) == iks[-1].hex())
