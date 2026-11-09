def add_item(item, cart=[]):
    """Add an item to the cart and return the cart."""
    cart.append(item)
    return cart


def cart_total(cart):
    return sum(entry["price"] for entry in cart)
