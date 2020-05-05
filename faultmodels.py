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

def single_row_corruption(s):
    j = random.choice(range(4))
    for i in range(3):
	    s[i][j] = random.randint(0, 255)

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

def single_bit_every_byte(s):
    for i in range(4):
        for j in range(4):
            bit = random.choice(range(8))
            s[i][j] = s[i][j] ^ (1<<bit)