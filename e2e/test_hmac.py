async def test_hmac_sha256(client):
    result = await client.call_tool("hmac", {"message": "hello", "key": "secret"})
    assert result.content[0].text == (
        "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
    )
