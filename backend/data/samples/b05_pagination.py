def paginate(items, page_size):
    """Split items into pages of page_size."""
    pages = []
    current = []
    for i in range(1, len(items)):
        current.append(items[i])
        if len(current) == page_size:
            pages.append(current)
            current = []
    if current:
        pages.append(current)
    return pages
