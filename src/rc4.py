iv = [0x58, 0x94, 0x22]
wep_key = [0xB3, 0xF0, 0xCA, 0xA8, 0xBB, 0xD6, 0xB8, 0x6E, 0x05, 0x02, 0x24,
0x9E, 0x09]
key = iv + wep_key
M = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00,
0x06, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xff, 0xff, 0xff,
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]
nums_in_line = 16
print "M =\n", '\n'.join([' '.join([hex(Mi)[2:].zfill(2)
    for Mi in M[i * nums_in_line:(i+1)*nums_in_line]])
        for i in xrange(len(M) / nums_in_line + 1)])

C = []
keylength = len(key)
S = range(256)

# KSA
j = 0
for i in xrange(256):
    j = (j + S[i] + key[i % keylength]) % 256
    S[i], S[j] = S[j], S[i]

# PRGA
print "K =\n",
i, j = 0, 0
for Mi in M:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    K = S[(S[i] + S[j]) % 256]
    print hex(K)[2:].zfill(2) + ('\n' if not (i % nums_in_line) else ''),
    C.append(Mi ^ K)

# Output chiphertext
print "\nC =\n", '\n'.join([' '.join([hex(Ci)[2:].zfill(2)
    for Ci in C[i*nums_in_line:(i+1)*nums_in_line]])
        for i in xrange(len(C) / nums_in_line + 1)])
