const jsbtc = require('./src/jsbtc.js');

async function reproduce() {
    await jsbtc.asyncInit(global);
    
    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    console.log("Input Mnemonic:", mnemonic);
    
    try {
        // threshold is invalid ($)
        const shares = splitMnemonic("$", 3, mnemonic, {embeddedIndex: true});
        console.log("\nGenerated Shares (Threshold: $):");
        shares.forEach((s, i) => {
            console.log(`Share ${i+1}: ${s}`);
        });
        
        // Check if entropy is duplicated
        const word1 = shares[0].split(" ").slice(0, 11).join(" ");
        const word2 = shares[1].split(" ").slice(0, 11).join(" ");
        
        if (word1 === word2) {
            console.log("\n❌ BUG CONFIRMED: Entropy is duplicated across shares!");
        } else {
            console.log("\n✅ NO BUG: Entropy is unique.");
        }
    } catch (e) {
        console.log("\n✅ CAUGHT ERROR:", e.message);
    }
}

reproduce();