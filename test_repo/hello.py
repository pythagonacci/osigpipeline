#!/usr/bin/env python3
"""
Simple test module for UCG pipeline testing.
"""

import os
from typing import List, Optional


def greet(name: str) -> str:
    """Return a greeting message."""
    return f"Hello, {name}!"


def process_items(items: List[str]) -> List[str]:
    """Process a list of items."""
    results = []
    for item in items:
        if item:
            processed = item.upper()
            results.append(processed)
    return results


class Calculator:
    """Simple calculator class."""
    
    def __init__(self, initial_value: int = 0):
        self.value = initial_value
    
    def add(self, x: int) -> int:
        """Add a number to the current value."""
        self.value += x
        return self.value
    
    def multiply(self, x: int) -> int:
        """Multiply the current value by a number."""
        self.value *= x
        return self.value


def main():
    """Main function."""
    print(greet("World"))
    
    calc = Calculator(10)
    result = calc.add(5)
    print(f"Result: {result}")
    
    items = ["hello", "world", "python"]
    processed = process_items(items)
    print(f"Processed: {processed}")


if __name__ == "__main__":
    main()
