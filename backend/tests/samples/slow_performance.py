"""Sample built around nested loops: performance should suffer."""


def find_duplicates(left, right):
    """Compare every item with every other item."""
    matches = []
    for first in left:
        for second in right:
            if first == second:
                matches.append(first)
    return matches


def build_matrix(rows, columns):
    """Two more nested loops."""
    matrix = []
    for row in rows:
        line = []
        for column in columns:
            line.append(row * column)
        matrix.append(line)
    return matrix


def totals(groups):
    """And a third, over a nested structure."""
    result = []
    for group in groups:
        running = 0
        for member in group:
            running += member
        result.append(running)
    return result
