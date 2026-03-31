GET {{baseurl}}/info
HTTP 200
[Asserts]
jsonpath "$['std:name']" == "crypto"
jsonpath "$['std:version']" isString
