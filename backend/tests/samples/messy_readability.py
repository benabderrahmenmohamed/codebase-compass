"""Sample where names and literals say nothing: readability should suffer."""


def compute(rows):
    data = []
    tmp = 0
    for row in rows:
        if row > 42:
            tmp = tmp + row * 17
            data.append(tmp)
    return data


def summarise(rows):
    res = compute(rows)
    val = len(res)
    banner = "the quick brown fox jumps over the lazy dog and keeps running well past the end of this line"
    return banner, val


def convert(amount):
    return amount * 1609 / 1000
