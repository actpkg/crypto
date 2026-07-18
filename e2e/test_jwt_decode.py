import json

TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    ".Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A"
)


async def test_decodes_a_valid_token(client):
    result = await client.call_tool("jwt_decode", {"token": TOKEN})
    # Measured: crypto's jwt_decode does not populate structured_content —
    # the payload only ever arrives as a JSON-encoded text block. It is
    # still real JSON, so parse it and assert on fields rather than doing
    # substring matching on the raw string; that stays strictly stronger
    # than `contains` even without a populated structured_content.
    assert result.structured_content is None
    decoded = json.loads(result.content[0].text)
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["claims"]["sub"] == "1234567890"
    assert decoded["claims"]["name"] == "John Doe"


async def test_rejects_a_malformed_token(client, expect_error):
    # Task 1 measured this: it comes back as an isError RESULT carrying
    # dev.actcore/error-kind = "std:invalid-args", NOT as a raised exception,
    # because call-tool has no result<> wrapper for a guest to fail through.
    await expect_error(client, "jwt_decode", {"token": "not-a-jwt"}, "std:invalid-args")
