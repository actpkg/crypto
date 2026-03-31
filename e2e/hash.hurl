# SHA-256 (default)
POST {{baseurl}}/tools/hash
{"arguments": {"input": "hello"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].text" == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

# SHA-512
POST {{baseurl}}/tools/hash
{"arguments": {"input": "hello", "algorithm": "sha512"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].text" == "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"

# SHA3-256
POST {{baseurl}}/tools/hash
{"arguments": {"input": "hello", "algorithm": "sha3-256"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].text" == "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"
