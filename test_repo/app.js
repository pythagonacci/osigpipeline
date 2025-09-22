// Simple JavaScript test file for UCG pipeline testing

function greet(name) {
    return `Hello, ${name}!`;
}

function processItems(items) {
    const results = [];
    for (const item of items) {
        if (item) {
            const processed = item.toUpperCase();
            results.push(processed);
        }
    }
    return results;
}

class Calculator {
    constructor(initialValue = 0) {
        this.value = initialValue;
    }
    
    add(x) {
        this.value += x;
        return this.value;
    }
    
    multiply(x) {
        this.value *= x;
        return this.value;
    }
}

function main() {
    console.log(greet("World"));
    
    const calc = new Calculator(10);
    const result = calc.add(5);
    console.log(`Result: ${result}`);
    
    const items = ["hello", "world", "javascript"];
    const processed = processItems(items);
    console.log(`Processed: ${processed}`);
}

// Export for module usage
module.exports = {
    greet,
    processItems,
    Calculator,
    main
};
