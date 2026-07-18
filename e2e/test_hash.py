import pytest

CASES = [
    (None, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
    ("sha512", "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7"
               "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"),
    ("sha3-256", "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"),
    ("md5", "5d41402abc4b2a76b9719d911017c592"),
    ("sha1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
    ("sha3-512", "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df"
                 "891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976"),
]


@pytest.mark.parametrize("algorithm,expected", CASES)
async def test_hash_of_hello(client, algorithm, expected):
    args = {"input": "hello"}
    if algorithm is not None:
        args["algorithm"] = algorithm
    result = await client.call_tool("hash", args)
    assert result.content[0].text == expected
