const crypto = require('crypto');

/**
 * Find a nonce such that SHA256(data_prefix + nonce) starts with required_zeros zeros.
 * 
 * @param {string} dataPrefix - The base data to hash
 * @param {number} requiredZeros - Number of leading zeros required
 * @returns {Promise<[number, string]>} - Tuple containing nonce and hash_value
 */
async function findNonceWithLeadingZeros(dataPrefix = "", requiredZeros = 5) {
    // Create the target prefix (e.g., "00000" for 5 zeros)
    const targetPrefix = "0".repeat(requiredZeros);
    
    // Start with nonce = 0 and increment
    let nonce = 0;
    
    while (true) {
        // Combine the data prefix with the nonce
        const inputData = dataPrefix + nonce.toString();
        
        // Calculate SHA256 hash
        const hash = crypto.createHash('sha256');
        hash.update(inputData);
        const hashResult = hash.digest('hex');
        
        // Check if hash starts with the required number of zeros
        if (hashResult.startsWith(targetPrefix)) {
            return [nonce, hashResult];
        }
        
        // Increment nonce for next iteration
        nonce++;
        
        // Optional: Add a progress indicator for very long searches
        // Using setImmediate to prevent blocking the event loop
        if (nonce % 1000000 === 0) {
            // Use process.stderr for error output similar to Python
            process.stderr.write(`Tried ${nonce.toLocaleString()} nonces...\n`);
            
            // Yield to event loop to prevent blocking
            await new Promise(resolve => setImmediate(resolve));
        }
    }
}

/**
 * Main function to demonstrate the nonce finding process.
 */
async function main() {
    // You can customize the data prefix if needed
    const dataPrefix = "Hello, World! ";
    
    console.log("Searching for a nonce that produces a SHA256 hash starting with 5 zeros...");
    console.log(`Data prefix: '${dataPrefix}'`);
    console.log("This might take a moment...\n");
    
    try {
        // Find the nonce
        const [nonce, hashValue] = await findNonceWithLeadingZeros(dataPrefix, 5);
        
        // Print the results
        console.log(`Found nonce: ${nonce}`);
        console.log(`Input data: '${dataPrefix + nonce}'`);
        console.log(`SHA256 hash: ${hashValue}`);
        console.log(`✓ Hash starts with '00000': ${hashValue.startsWith('00000')}`);
        
        return [nonce, hashValue];
        
    } catch (error) {
        if (error.message === 'Search interrupted') {
            console.log("\n\nSearch interrupted by user.");
        } else {
            console.error("Error:", error);
        }
        process.exit(1);
    }
}

// Handle Ctrl+C interruption
process.on('SIGINT', () => {
    console.log("\n\nSearch interrupted by user.");
    process.exit(1);
});

// Run the main function if this script is executed directly
if (require.main === module) {
    main().then(([nonce, hashValue]) => {
        console.log(`\nSuccessfully found nonce ${nonce} with hash ${hashValue}`);
    }).catch(error => {
        console.error("Unexpected error:", error);
        process.exit(1);
    });
}

// Export the function for use in other modules
module.exports = { findNonceWithLeadingZeros, main };