#!/usr/bin/env python3

import json
import sys


data = json.load(sys.stdin)[0]
row_order = ["Total", "Critical", "High", "Medium", "Low", "Not Applicable"]
column_order = [
    "Passed :white_check_mark:",
    "Failed :x:",
    "Not Reviewed :leftwards_arrow_with_hook:",
    "Not Applicable :heavy_minus_sign:",
    "Error :warning:",
]
column_widths = [max(len(row), len(column)) for row, column in zip(row_order, column_order)]
column_widths = [max(column_widths)] * len(column_widths)

table = (
    "| Compliance: "
    + str(data["compliance"])
    + "% :test_tube: | "
    + " | ".join(column.ljust(width) for column, width in zip(column_order, column_widths))
    + " |\n"
)
table += (
    "| "
    + "-".ljust(max(column_widths), "-")
    + " | "
    + " | ".join("-".ljust(width, "-") for width in column_widths)
    + " |\n"
)

for row in row_order:
    if row == "Total":
        values = [
            str(data["passed"]["total"]),
            str(data["failed"]["total"]),
            str(data["skipped"]["total"]),
            str(data["no_impact"]["total"]),
            str(data["error"]["total"]),
        ]
    elif row == "Not Applicable":
        values = ["-", "-", "-", str(data["no_impact"]["total"]), "-"]
    else:
        values = [
            str(data["passed"][row.lower()]),
            str(data["failed"][row.lower()]),
            str(data["skipped"][row.lower()]),
            "-",
            str(data["error"][row.lower()]),
        ]
    table += (
        "| "
        + ("**" + row + "**").ljust(max(column_widths) + 2)
        + " | "
        + " | ".join(value.ljust(width) for value, width in zip(values, column_widths))
        + " |\n"
    )

print(table)
