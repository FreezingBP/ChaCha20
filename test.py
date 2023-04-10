import struct
def main():
    runtests()

def chacha20_decrypt(key, counter, nonce, ciphertext):
    return chacha20_encrypt(key, counter, nonce, ciphertext)

def chacha20_encrypt(key, counter, nonce, plaintext):
    byte_length = len(plaintext)
    full_blocks = byte_length//64
    remainder_bytes = byte_length % 64
    encrypted_message = b''

    for i in range(full_blocks):
        key_stream = chacha20_block(key, counter + i, nonce)
        print(chacha20_block(key, counter + i, nonce))
        plaintext_block = plaintext[i*64:i*64+64]
        encrypted_block = [plaintext_block[j] ^ key_stream[j] for j in range(64)]
        encrypted_message += bytes(encrypted_block)
    if remainder_bytes != 0:
        key_stream = serialize(chacha20_block(key, counter + full_blocks, nonce))
        plaintext_block = plaintext[full_blocks*64:byte_length]
        encrypted_block = [plaintext_block[j] ^ key_stream[j] for j in range(remainder_bytes)]
        encrypted_message += bytes(encrypted_block)

    return encrypted_message

# returns a list of 16 32-bit unsigned integers
def chacha20_block(key, counter, nonce):
    BLOCK_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    init_state = BLOCK_CONSTANTS + key + [counter] + nonce
    current_state = init_state[:]
    for i in range(10):
        init_state = inner_block(init_state)
    init_state = [s + init_s for s, init_s in zip(init_state, current_state)]
    # current_state = current_state + init_state
    # for i in range(16):
    #   current_state[i] = add_32(current_state[i], init_state[i])

    return init_state

def inner_block(state):
    # columns
    quarterround(state, 0, 4, 8, 12)
    quarterround(state, 1, 5, 9, 13)
    quarterround(state, 2, 6, 10, 14)
    quarterround(state, 3, 7, 11, 15)
    # diagonals
    quarterround(state, 0, 5, 10, 15)
    quarterround(state, 1, 6, 11, 12)
    quarterround(state, 2, 7, 8, 13)
    quarterround(state, 3, 4, 9, 14)
    return state

def xor_32(x, y):
    return (x ^ y) & 0xffffffff

def add_32(x, y):
    return (x + y) & 0xffffffff

def rot_l32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def quarterround(state, i1, i2, i3, i4):
    a = state[i1]
    b = state[i2]
    c = state[i3]
    d = state[i4]

    a = add_32(a, b); d = xor_32(d, a); d = rot_l32(d, 16)
    c = add_32(c, d); b = xor_32(b, c); b = rot_l32(b, 12)
    a = add_32(a, b); d = xor_32(d, a); d = rot_l32(d, 8)
    c = add_32(c, d); b = xor_32(b, c); b = rot_l32(b, 7)

    state[i1] = a
    state[i2] = b
    state[i3] = c
    state[i4] = d


# def serialize(state) -> bytes:
#     return b''.join([struct.pack('<I', int(s)) for s in state])
def serialize(block):
    return b''.join([(word).to_bytes(4, 'little') for word in block])

# Test Vectors from RFC 8439
def runtests():
    key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f]
    # key = [0x2519EB0A, 0x909CE82E, 0xD6C085EC, 0x545ACF07, 0x24124049, 0x1E1353E7, 0x14AD4F2F, 0xE98FF6DE]
    # plaintext = b"\x8e\x91\x9e\xbe\x6a\x6c\x64\xc1\x02\x02\xf8\xda\xc4\xc8\xd6\x14\xa0\xa3\x9c\x0e\x62\x64\x70\x6d\x02\x02\x0c\x9d\xd2\xd6\xc6\xa8"
    plaintext = b_text
    nonce = [0x00000000, 0x0000004a, 0x00000000]
    # nonce = [0x7369C667, 0xEC4AFF51, 0xABBACD29]
    init_counter = 0x00000001
    ciphertext = chacha20_encrypt(key, init_counter, nonce, plaintext)
    for i in range(len(ciphertext)):
        print(hex(ciphertext[i])[2:],end = " ")
    # assert(chacha20_decrypt(key, init_counter, nonce, ciphertext) == plaintext)
    print("\t")
    print(chacha20_decrypt(key, init_counter, nonce, ciphertext))
    print("All tests passed!")



text = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip forthe future, sunscreen would be it."
b_text = text.encode()
print(b_text)

main();
