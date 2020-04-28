from submod.aes.aes import AES, matrix2bytes
from submod.JeanGrey.phoenixAES import phoenixAES
import random, os

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

    'mc7',
    'ark7',
    'sb8',
    'sr8',

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
    print(f'--{intermediate}--')
    faulted = []
    for _ in range(10):
        faulted.append(os.urandom(16))
    # for _ in range(200):
    #     faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_bit_flip))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_byte_corruption))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_col_corruption))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_byte_multi_bit_flip))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=double_byte_multi_bit_flip))
        # faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=triple_byte_multi_bit_flip))
        # print(f'faulted    : {faulted[-1].hex()}')
    random.shuffle(faulted)
    # roundkey, idx, candidates = phoenixAES.crack_bytes(faulted, ciphertext, verbose=0, encrypt=True)
    # print(f"roundkey   : {''.join(['%02x' % x if x is not None else '..' for x in roundkey])} ({idx}, {intermediate})")
    roundkey, idx, candidates = phoenixAES.crack_bytes(faulted, ciphertext, verbose=0, encrypt=True)
    print(f"roundkey   : {''.join(['%02x' % x if x is not None else '..' for x in roundkey])} ({idx}, {intermediate})")
    if None in roundkey:
        # roundkey, idx, candidates = phoenixAES.crack_bytes(
        #     phoenixAES.convert_r8faults_bytes(faulted, ciphertext), ciphertext, verbose=0, encrypt=True)
        # print(f"roundkey   : {''.join(['%02x' % x if x is not None else '..' for x in roundkey])} ({idx}, {intermediate})")
        roundkey, idx, candidates = phoenixAES.crack_bytes(
            phoenixAES.convert_r8faults_bytes(faulted, ciphertext), ciphertext, verbose=0, encrypt=True)
        print(f"roundkey   : {''.join(['%02x' % x if x is not None else '..' for x in roundkey])} ({idx}, {intermediate})")
    # print(candidates)



# print('--encrypt--')
# for intermediate in intermediates:
#     print(f'--{intermediate}--')
#     output = []
#     candidates=[[], [], [], []]
#     recovered=[False, False, False, False]
#     key=[None]*16
#     prev=''
#     for ctr in range(int(1e6)):
#         r = random.randint(0,255)
#         if r == 0:
#             output.append(os.urandom(16))
#         elif r == 1:
#             output.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=single_bit_flip))
#         else:
#             output.append(ciphertext)

#         phoenixAES.crack_bytes_rolling(output[-1], ciphertext, candidates, recovered, key, verbose=0, encrypt=True)
#         new=''.join(['%02x' % x if x is not None else '..' for x in key])
#         if prev != new:
#             print(new, ctr)
#             prev = new
#         # print(recovered)
#         if not False in recovered:
#             break
#     print(ctr)
#     print(iks[-1].hex(), iks[-1].hex() == ''.join(['%02x' % x if x is not None else '..' for x in key]))

#     roundkey, idx, candidates = phoenixAES.crack_bytes(output, ciphertext, verbose=0, encrypt=True)
#     print(f"roundkey   : {''.join(['%02x' % x if x is not None else '..' for x in roundkey])} ({idx}, {intermediate})")



# print('--decrypt--')
# for intermediate in intermediates:
#     faulted = []
#     for _ in range(50):
#         faulted.append(ctx.decrypt_block(bytes(ciphertext), glitch_at=intermediate))
#         # print(f'faulted    : {faulted[-1].hex()}')
#     recovered, idx = phoenixAES.crack_bytes(faulted, message, verbose=0, encrypt=False)
#     if recovered:
#         print(f'recovered  : {recovered.hex()} ({idx}, {intermediate})')

faulted = [
    bytes.fromhex('ab73e91362fc2db70d99cce0aa2deecf'),
    bytes.fromhex('abf73f13ff062db79a99cc3faa2d1eca'),
    bytes.fromhex('abf7745fff5330b769cbcc3f882d1e3f'),
    bytes.fromhex('ab06eb13e8742db74a99ccbdaa2db4e9'),
    bytes.fromhex('abdbe9ef62fc87b70dbccc9c5e2d49cf'),
    bytes.fromhex('abcee9139dfc2db70d99ccadaa2d0bcf'),
    bytes.fromhex('abf74741ff2e0fb76e55cc3f772d1eab'),
    bytes.fromhex('abf79613ff0a2db73899cc3faa2d1ecb'),
    bytes.fromhex('e1f7d613ffa82dc46c993d3faa8f1ec4'),
    bytes.fromhex('5af72013ff732dc41899013faa781ee0'),
    bytes.fromhex('abf7e970fffc1ab70d8ccc3f9f2d1ecf'),
    bytes.fromhex('ab18e923eefcb4b70db3cc81fa2d5fcf'),
    bytes.fromhex('8b36e9131afc2d970d99cf36aa8f49cf'),
    bytes.fromhex('ab4334130af12db78499ccd3aa2de639'),
    bytes.fromhex('aef7e913fffc2d8f0d99643faabe1ecf'),
    bytes.fromhex('abf7e15effbf55b730c8cc3f772d1e45'),
    bytes.fromhex('ab6ae9133afc2db70d99cc85aa2d52cf'),
    bytes.fromhex('417ce91322fc2d820d9965d8aa372ecf'),
    bytes.fromhex('b2f7e97efffc15a50dfac03f32561ecf'),
    bytes.fromhex('c7dbe91389fc2dc60d99cdcdaa8cd7cf'),
    bytes.fromhex('ab62e913d4fc2db70d99ccc8aa2de8cf'),
    bytes.fromhex('abf7e994fffc67b70d41cc3ff22d1ecf'),
    bytes.fromhex('ab9ee9b234fc70b70df2cc40862d9ecf'),
    bytes.fromhex('abf76713ffca2db70899cc3faa2d1ee7'),
    bytes.fromhex('c7f7e9cefffc12f00dffd83f19661ecf'),
    bytes.fromhex('ab657a133b192db7e499cc51aa2dc7e6'),
    bytes.fromhex('72f7e941fffc037a0d08373fb5591ecf'),
    bytes.fromhex('5af7e954fffca6c40d61013f90781ecf'),
    bytes.fromhex('ab52771305912db71099ccbfaa2dfa16'),
    bytes.fromhex('9da6e913c8fc2d180d99148caad236cf'),
    bytes.fromhex('da2fe913f0fc2ddb0d99f8e1aaa2fecf'),
    bytes.fromhex('abf72013ffdc2db78e99cc3faa2d1e84'),
    bytes.fromhex('21b2e91319fc2d440d994d8baa1852cf'),
    bytes.fromhex('00f7f713ff392d8acd992d3faa5d1e26'),
    bytes.fromhex('ab3de9136afc2db70d99cc0faa2d7ccf'),
    bytes.fromhex('8cf7f413ffc82ddbf399e03faa071e9d'),
    bytes.fromhex('abfb341381372db74799cce7aa2d2e74'),
    bytes.fromhex('11f79713ffdb2d8bbc99623faad51e05'),
    bytes.fromhex('abcec31309e42db72899ccd1aa2d2ebe'),
    bytes.fromhex('abae3f135aca2db7c299ccd3aa2d95ee'),
    bytes.fromhex('213be91325fc2d440d994d24aa18a0cf'),
    bytes.fromhex('ab949713a9612db78d99cceaaa2d2c7c'),
    bytes.fromhex('abf7e963fffc5cb70dd9cc3f8c2d1ecf'),
    bytes.fromhex('fa1ce913edfc2dfb0d9956b6aa45a9cf'),
    bytes.fromhex('8bd4e91332fc2da50d99ace8aa1bdfcf'),
    bytes.fromhex('daa6e913f1fc2d6c0d994de8aa8e1ccf'),
    bytes.fromhex('ab282713d37d2db7ab99cc73aa2dee6d'),
    bytes.fromhex('ab6096135a592db7aa99cc84aa2dee12'),
    bytes.fromhex('0ef7e95efffca0d20d55593f264f1ecf'),
    bytes.fromhex('daf73813ff282d445199d83faa0e1e6e'),
    bytes.fromhex('abfbbb1381f92db71a99cce7aa2d2e75'),
    bytes.fromhex('4620e9139dfc2dd80d9985e5aa3c54cf'),
    bytes.fromhex('abf765a5ffce57b73f60cc3f822d1e4a'),
    bytes.fromhex('ab9ee913f7fc2db70d99ccceaa2d45cf'),
    bytes.fromhex('c8a5e9136cfc2d8e0d99472faace0fcf'),
    bytes.fromhex('46ece91343fc2d170d9990a6aacc00cf'),
    bytes.fromhex('abf738d3ff5f45b794bccc3f742d1e47'),
    bytes.fromhex('6ff7e913fffc2d940d993c3faa0a1ecf'),
    bytes.fromhex('9bf7e9a9fffcb6be0d26793f73c41ecf'),
    bytes.fromhex('2dcde9135dfc2d330d999873aaa0f8cf'),
    bytes.fromhex('007fe913a6fc2d8a0d992d04aa5d40cf'),
    bytes.fromhex('abf7e9d1fffc88b70db6cc3f142d1ecf'),
    bytes.fromhex('11f7e9f2fffcfca20dde7a3fd8e31ecf'),
    bytes.fromhex('abf7f913ff322db7b299cc3faa2d1ec9'),
    bytes.fromhex('abc9e9411dfca0b70dc8ccc0e02dc2cf'),
    bytes.fromhex('cd7be913f8fc2dae0d9970d0aafef6cf'),
    bytes.fromhex('abf72a93ff2ed4b7499dcc3f0f2d1efc'),
    bytes.fromhex('abffe91333fc2db70d99cc12aa2de3cf'),
    bytes.fromhex('abf797c6ff3868b73903cc3f0d2d1eb3'),
    bytes.fromhex('93f7e9bffffcb6ef0dfac73f36ac1ecf'),
    bytes.fromhex('5df78813ff742dc4a799cf3faaa51ed3'),
    bytes.fromhex('abf75e11ff50b1b73660cc3f6b2d1e66'),
    bytes.fromhex('abf7674eff0b4cb7af94cc3faf2d1eea'),
    bytes.fromhex('abf7e954fffc78b70d14cc3fd62d1ecf'),
    bytes.fromhex('93f7e613ff962dfa0099783faa051e32'),
    bytes.fromhex('83f7d613ffa82dc76c99be3faa421ec4'),
    bytes.fromhex('79f7e9d3fffc45860dbc203f74491ecf'),
    bytes.fromhex('abf731a1ff4aa6b76c43cc3fd12d1ebf'),
    bytes.fromhex('abf7cd64ff8480b70a71cc3f3f2d1ee6'),
    bytes.fromhex('abf7e940fffcc3b70d4ccc3fd02d1ecf'),
    bytes.fromhex('ab2f1513200b2db7bc99ccc5aa2d6e7c'),
    bytes.fromhex('21f7e913fffc2d290d99383faa9f1ecf'),
    bytes.fromhex('abf77a86ffd9c7b7c139cc3fde2d1e23'),
    bytes.fromhex('abc7e913dffc2db70d99cc9caa2dd7cf'),
    bytes.fromhex('34f7e923fffcf7ef0d72473f4d471ecf'),
    bytes.fromhex('ab6fe91305fc2db70d99cc13aa2d3dcf'),
    bytes.fromhex('abc5e93eb7fc45b70d33cc21a42dcacf'),
    bytes.fromhex('abf7778bff91ceb71054cc3f892d1e16'),
    bytes.fromhex('abf71013ff062db7b799cc3faa2d1ecc'),
    bytes.fromhex('abf78c13ff912db70d99cc3faa2d1e81'),
    bytes.fromhex('34f7e941fffc03fb0d08633fb5ce1ecf'),
    bytes.fromhex('ab8de913f3fc2db70d99cc61aa2d94cf'),
    bytes.fromhex('ab57e9b79cfc70b70d73cc6c202de3cf'),
    bytes.fromhex('b0f7e945fffcc0a60d84f23f52e01ecf'),
    bytes.fromhex('abf71792ff4213b7eb36cc3f2c2d1e58'),
    bytes.fromhex('abc4e9ed32fcfbb70d97cc2b492dddcf'),
    bytes.fromhex('abf7e919fffc26b70d04cc3ff52d1ecf'),
    bytes.fromhex('b7dbe91362fc2d2c0d99879caa2f49cf'),
    bytes.fromhex('2cf7e947fffc215b0dc8873f39a91ecf'),
    bytes.fromhex('abf7f72eff19a1b70828cc3f732d1e23'),
    bytes.fromhex('e3f7e913fffc2d1c0d99c83faa0f1ecf'),
    bytes.fromhex('abf7df47ff8ff7b79081cc3fce2d1ec4'),
    bytes.fromhex('ab93e9138ffc2db70d99ccb6aa2d88cf'),
    bytes.fromhex('9bf7e9a9fffca1020de5ec3f79491ecf'),
    bytes.fromhex('abf7061eff4507b77ececc3f172d1ef9'),
    bytes.fromhex('abf79813ff0a2db72599cc3faa2d1e2f'),
]

# print('--encrypt--')
# for intermediate in ['sb9']:
#     print(f'--{intermediate}--')
#     # faulted = []
#     # # # for _ in range(10000):
#     # # #     faulted.append(os.urandom(16))
#     # for _ in range(500):
#     #     faulted.append(ctx.encrypt_block(bytes(message), glitch_at=intermediate, glitch=double_byte_multi_bit_flip))
#     # random.shuffle(faulted)
#     # for f in faulted:
#     #     print(f"bytes.fromhex('{f.hex()}'),")
#     roundkey, idx, candidates = phoenixAES.crack_bytes(faulted[:200], ciphertext, verbose=0, encrypt=True)
#     print(f"roundkey   : {''.join(['%02x' % x if x is not None else '..' for x in roundkey])} ({idx}, {intermediate})")
#     # print(candidates)

# with open('tracefile', 'w') as t:
#     print(ciphertext.hex(), file=t)
#     for f in faulted:
#         print(f.hex(), file=t)

# cracker = phoenixAES.ByteCracker(ciphertext, encrypt=True, verbose=0)
# for faulty in faulted:
#     roundkey, idx, candidates = cracker.crack_bytes(faulty)
#     print(f"roundkey   : {''.join(['%02x' % x if x is not None else '..' for x in roundkey])} ({idx})")