# SHA-256 (default)
POST {{baseurl}}/tools/hash
{"arguments": {"input": "hello"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

# SHA-512
POST {{baseurl}}/tools/hash
{"arguments": {"input": "hello", "algorithm": "sha512"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" == "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"

# SHA3-256
POST {{baseurl}}/tools/hash
{"arguments": {"input": "hello", "algorithm": "sha3-256"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" == "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"

# MD5
POST {{baseurl}}/tools/hash
{"arguments": {"input": "hello", "algorithm": "md5"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" == "5d41402abc4b2a76b9719d911017c592"

# SHA-1
POST {{baseurl}}/tools/hash
{"arguments": {"input": "hello", "algorithm": "sha1"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

# SHA3-512
POST {{baseurl}}/tools/hash
{"arguments": {"input": "hello", "algorithm": "sha3-512"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" == "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976"
