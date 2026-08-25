/*
 * Shamir's Secret Sharing implementation for BIP39 mnemonics
 * Based on SLIP-39 specification
 */

const S = {};

// Galois Field arithmetic (GF(256))
const GF256 = {
  // Addition in GF(256) is XOR
  add: (a, b) => a ^ b,
  sub: (a, b) => a ^ b,
  
  // Multiplication in GF(256)
  mul: (a, b) => {
    let result = 0;
    while (b > 0) {
      if (b & 1) result ^= a;
      a <<= 1;
      if (a & 0x100) a ^= 0x11d; // x^8 + x^4 + x^3 + x + 1
      b >>= 1;
    }
    return result;
  },
  
  // Division in GF(256)
  div: (a, b) => {
    if (b === 0) throw new Error('Division by zero in GF(256)');
    // Using log/antilog tables would be faster, but this is simple
    let logA = 0, logB = 0;
    let temp = a;
    while (temp > 1) { temp = GF256.mul(temp, 2); logA++; }
    temp = b;
    while (temp > 1) { temp = GF256.mul(temp, 2); logB++; }
    let logResult = (logA - logB + 255) % 255;
    let result = 1;
    for (let i = 0; i < logResult; i++) result = GF256.mul(result, 2);
    return result;
  },
  
  // Inverse in GF(256)
  inv: (a) => {
    if (a === 0) throw new Error('Inverse of zero in GF(256)');
    // a^254 = a^-1 in GF(256)
    let result = 1;
    for (let i = 0; i < 254; i++) result = GF256.mul(result, a);
    return result;
  }
};

// Buffer concatenation helper
const BC = (buffers) => Buffer.concat(buffers);

// Buffer from array helper
const BF = (arr) => Buffer.from(arr);

// Generate random bytes
S.__random_bytes = (length) => {
  const buf = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    buf[i] = Math.floor(Math.random() * 256);
  }
  return buf;
};

// Shamir interpolation at x=0 (reconstruct secret)
S.__shamirInterpolation = (points) => {
  // points is array of [x, y] pairs
  // We want to evaluate polynomial at x=0
  // Using Lagrange interpolation: f(0) = sum(y_i * l_i(0))
  // where l_i(0) = product_{j != i} (0 - x_j) / (x_i - x_j)
  // = product_{j != i} (-x_j) / (x_i - x_j)
  // = product_{j != i} x_j / (x_j - x_i)  (since -1 = 1 in GF(256))
  
  let result = 0;
  for (let i = 0; i < points.length; i++) {
    const [xi, yi] = points[i];
    let numerator = 1;
    let denominator = 1;
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      const [xj] = points[j];
      numerator = GF256.mul(numerator, xj);
      denominator = GF256.mul(denominator, GF256.add(xj, xi)); // xj - xi = xj + xi in GF(256)
    }
    const li = GF256.mul(numerator, GF256.inv(denominator));
    result = GF256.add(result, GF256.mul(yi, li));
  }
  return result;
};

// Split secret into shares
// threshold: minimum number of shares needed to reconstruct
// total: total number of shares to generate
// secret: Buffer of 16 bytes (128 bits) for 12-word mnemonic
S.__split_secret = (threshold, total, secret) => {
  if (threshold < 2) throw new Error('Threshold must be at least 2');
  if (threshold > total) throw new Error('Threshold cannot exceed total shares');
  if (total > 255) throw new Error('Cannot generate more than 255 shares');
  if (!Buffer.isBuffer(secret) || secret.length !== 16) {
    throw new Error('Secret must be a 16-byte Buffer');
  }
  
  const shares = {};
  
  // For each byte of the secret, create a separate polynomial
  for (let byteIndex = 0; byteIndex < 16; byteIndex++) {
    const secretByte = secret[byteIndex];
    
    // Generate random coefficients for polynomial of degree (threshold - 1)
    // f(x) = secretByte + a1*x + a2*x^2 + ... + a_{threshold-1}*x^{threshold-1}
    const coefficients = [secretByte];
    for (let i = 1; i < threshold; i++) {
      coefficients.push(S.__random_bytes(1)[0]);
    }
    
    // Evaluate polynomial at x = 1, 2, ..., total
    for (let x = 1; x <= total; x++) {
      let y = 0;
      let xPower = 1;
      for (let coeff of coefficients) {
        y = GF256.add(y, GF256.mul(coeff, xPower));
        xPower = GF256.mul(xPower, x);
      }
      
      if (!shares[x]) shares[x] = Buffer.alloc(16);
      shares[x][byteIndex] = y;
    }
  }
  
  // Convert to array of {index, data} objects
  const result = [];
  for (let x = 1; x <= total; x++) {
    result.push({ index: x, data: shares[x] });
  }
  return result;
};

// Restore secret from shares
// shares: array of {index, data} objects or object with index keys
// threshold: minimum number of shares required (MUST be provided)
S.__restore_secret = (shares, threshold) => {
  // Convert shares to object format if array
  let sharesObj = {};
  if (Array.isArray(shares)) {
    for (const share of shares) {
      if (!share || typeof share.index !== 'number' || !Buffer.isBuffer(share.data)) {
        throw new Error('Invalid share format');
      }
      if (share.index < 1 || share.index > 255) {
        throw new Error('Share index out of range (1-255)');
      }
      if (share.data.length !== 16) {
        throw new Error('Share data must be 16 bytes');
      }
      sharesObj[share.index] = share.data;
    }
  } else if (typeof shares === 'object' && shares !== null) {
    for (const key of Object.keys(shares)) {
      const index = parseInt(key, 10);
      if (isNaN(index) || index < 1 || index > 255) {
        throw new Error('Share index out of range (1-255)');
      }
      const data = shares[key];
      if (!Buffer.isBuffer(data) || data.length !== 16) {
        throw new Error('Share data must be 16 bytes');
      }
      sharesObj[index] = data;
    }
  } else {
    throw new Error('Shares must be an array or object');
  }
  
  const shareCount = Object.keys(sharesObj).length;
  
  // CRITICAL FIX: Verify threshold is met
  if (threshold === undefined || threshold === null) {
    throw new Error('Threshold parameter is required for secret restoration');
  }
  if (shareCount < threshold) {
    throw new Error(`Insufficient shares: need at least ${threshold}, got ${shareCount}`);
  }
  
  // Reconstruct each byte of the secret
  let secret = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    const points = [];
    for (const indexStr of Object.keys(sharesObj)) {
      const index = parseInt(indexStr, 10);
      points.push([index, sharesObj[index][i]]);
    }
    secret[i] = S.__shamirInterpolation(points);
  }
  
  return secret;
};

// Public API
S.split_mnemonic = (threshold, total, mnemonic) => {
  // Validate mnemonic (basic check)
  const words = mnemonic.trim().split(/\s+/);
  if (words.length !== 12 && words.length !== 15 && words.length !== 18 && words.length !== 21 && words.length !== 24) {
    throw new Error('Invalid mnemonic length');
  }
  
  // Convert mnemonic to entropy (16 bytes for 12 words)
  // This is a simplified version - in reality you'd use bip39 library
  // For now, we'll assume the secret is already 16 bytes
  // The actual implementation would use bip39.mnemonicToEntropy
  
  // For compatibility with existing code, we'll use a placeholder
  // The real implementation should convert mnemonic to entropy first
  const secret = Buffer.from(mnemonic, 'utf8').slice(0, 16); // Placeholder
  
  return S.__split_secret(threshold, total, secret);
};

S.restore_mnemonic = (shares, threshold) => {
  const secret = S.__restore_secret(shares, threshold);
  // Convert entropy back to mnemonic
  // Placeholder - real implementation would use bip39.entropyToMnemonic
  return secret.toString('utf8'); // Placeholder
};

module.exports = S;
