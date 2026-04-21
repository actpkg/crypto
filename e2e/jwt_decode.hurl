# Decode a valid JWT
POST {{baseurl}}/tools/jwt_decode
{"arguments": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" contains "HS256"
jsonpath "$.content[0].data" contains "1234567890"
jsonpath "$.content[0].data" contains "John Doe"

# Invalid JWT
POST {{baseurl}}/tools/jwt_decode
{"arguments": {"token": "not-a-jwt"}}
HTTP 422
[Asserts]
jsonpath "$.error" exists
