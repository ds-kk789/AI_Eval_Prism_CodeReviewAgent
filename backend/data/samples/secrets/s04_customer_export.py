import csv

CUSTOMERS = [
    {"name": "Carol Ng", "email": "carol.ng@example.com", "phone": "+65 9123 4567"},
]


def export(path: str) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "email", "phone"])
        writer.writeheader()
        writer.writerows(CUSTOMERS)
