import struct
def add_32(x, y):
    return (x + y) & 0xffffffff

def xor_32(x, y):
    return (x ^ y) & 0xffffffff

def rot_l32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def quarter_round(a, b, c, d):
    a = add_32(a, b); d = xor_32(d, a); d = rot_l32(d, 16)
    c = add_32(c, d); b = xor_32(b, c); b = rot_l32(b, 12)
    a = add_32(a, b); d = xor_32(d, a); d = rot_l32(d, 8)
    c = add_32(c, d); b = xor_32(b, c); b = rot_l32(b, 7)
    return a, b, c, d

def Qround(state, idx1, idx2, idx3, idx4):
    state[idx1], state[idx2], state[idx3], state[idx4] = \
        quarter_round(state[idx1], state[idx2], state[idx3], state[idx4])

def inner_block(state):
    # columns
    Qround(state, 0, 4, 8, 12)
    Qround(state, 1, 5, 9, 13)
    Qround(state, 2, 6, 10, 14)
    Qround(state, 3, 7, 11, 15)
    # diagonals
    Qround(state, 0, 5, 10, 15)
    Qround(state, 1, 6, 11, 12)
    Qround(state, 2, 7, 8, 13)
    Qround(state, 3, 4, 9, 14)
    return state

def serialize(block):
    return b''.join([(word).to_bytes(4, 'little') for word in block])

def chacha20_block(key, counter, nonce):
    BLOCK_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    init_state = BLOCK_CONSTANTS + key + [counter] + nonce
    current_state = init_state[:]
    for i in range(10):
        inner_block(current_state)
    for i in range(16):
        current_state[i] = add_32(current_state[i], init_state[i])

    return serialize(current_state)

def xor(x: bytes, y: bytes):
    return bytes(a ^ b for a, b in zip(x, y))


def chacha20_encrypt(key, counter, nonce, plaintext):
    encrypted_message = bytearray(0)

    for j in range(len(plaintext) // 64):
        key_stream = chacha20_block(key, counter + j, nonce)
        block = plaintext[j * 64: (j + 1) * 64]
        encrypted_message += xor(block, key_stream)

    if len(plaintext) % 64 != 0:
        j = len(plaintext) // 64
        key_stream = chacha20_block(key, counter + j, nonce)
        block = plaintext[j * 64:]
        encrypted_message += xor(block, key_stream)

    return encrypted_message

def chacha20_decrypt(key, counter, nonce, ciphertext):
    return chacha20_encrypt(key, counter, nonce, ciphertext)


key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f]
text = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip forthe future, sunscreen would be it."
b_text = text.encode()
plaintext = b_text
nonce = [0x00000000, 0x0000004a, 0x00000000]
    # nonce = [0x7369C667, 0xEC4AFF51, 0xABBACD29]
init_counter = 0x00000001
ciphertext = chacha20_encrypt(key, init_counter, nonce, plaintext)
for i in range(len(ciphertext)):
    print(hex(ciphertext[i])[2:],end = " ")
print('\n')
print(chacha20_decrypt(key, init_counter, nonce, ciphertext))

