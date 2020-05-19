module.exports = function (S) {
    let BA = S.Buffer.alloc;
    let BF = S.Buffer.from;
    let BC = S.Buffer.concat;


    S.__precompute_GF256_expLog = (S) => {
        let exp = BA(255, 0);
        let log = BA(256, 0);
        let poly = 1;
        for (let i=0; i < 255; i++) {
            exp[i] = poly;
            log[poly] = i;
            // Multiply poly by the polynomial x + 1.
            poly = (poly << 1) ^ poly;
            // Reduce poly by x^8 + x^4 + x^3 + x + 1
            if (poly & 0x100) poly ^= 0x11b;
        }
        S.GF256_EXP_TABLE = exp;
        S.GF256_LOG_TABLE = log;
    };

    S.__GF256_mul = (a, b) => {
        if ((a === 0) || (b === 0)) return 0;
        return S.GF256_EXP_TABLE[S.__mod(S.GF256_LOG_TABLE[a] + S.GF256_LOG_TABLE[b], 255)];
    };

    S.__GF256_pow = (a, b) => {
        if (b === 0) return 1;
        if (a === 0) return 0;
        let c = a;
        for (let i = 0; i < b-1; i++) c = S.__GF256_mul(c, a);
        return c;
    };

    S.__mod = (a, b) => ((a%b) + b) % b;

    S.__GF256_add = (a, b) => a ^ b;

    S.__GF256_sub = (a, b) => a ^ b;

    S.__GF256_inverse = (a) => {
        if (a === 0) throw new Error("Zero division");
        return S.GF256_EXP_TABLE[S.__mod(-1 * S.GF256_LOG_TABLE[a], 255)];
    };

    S.__GF256_div = (a, b) => {
        if (b === 0) throw new Error("Zero division");
        if (a === 0) return 0;
        let r = S.GF256_EXP_TABLE[S.__mod(S.GF256_LOG_TABLE[a] - S.GF256_LOG_TABLE[b], 255)];
        // let r = S.__GF256_mul(a, S.__GF256_inverse(b));
        if (a !== S.__GF256_mul(r, b)) throw new Error("failed");
        return r;
    };

    S.__shamirFn = (x, q) => {
        let r = 0;
        for (let a of q) r = S.__GF256_add(r, S.__GF256_mul(a, S.__GF256_pow(x, q.indexOf(a))));
        return r;
    };

    S.__shamirInterpolation = (points) => {
        let k = points.length;
        if (k<2) throw new Error("Minimum 2 points required");
        points.sort((a,b) => a[0] - b[0]);
        let z = new Set();
        for (let i of points) z.add(i[0]);
        if (z.size !== points.length) throw new Error("Unique points required");
        let p_x = 0;
        for (let j = 0; j < k; j++) {
            let p_j_x = 1;
            for (let m = 0; m < k; m++) {
                if (m===j) continue;
                // let a = S.__GF256_sub(x, points[m][0]);
                let a = points[m][0];
                // let b = S.__GF256_sub(points[j][0], points[m][0]);
                let b = S.__GF256_add(points[j][0], points[m][0]);
                let c = S.__GF256_div(a, b);
                p_j_x = S.__GF256_mul(p_j_x, c);
            }
            p_j_x = S.__GF256_mul(points[j][1], p_j_x);
            p_x = S.__GF256_add(p_x, p_j_x);
        }
        return p_x;
    };


    S.__split_secret = (threshold, total,  secret, indexBits=8) => {
        if (threshold > 255) throw new Error("threshold limit 255");
        if (total > 255) throw new Error("total limit 255");
        let index_mask = 2**indexBits - 1;
        if (total > index_mask) throw new Error("index bits is to low");
        if (threshold > total) throw new Error("invalid threshold");
        let shares = {};
        let sharesIndexes = [];

        let e = S.generateEntropy({hex:false});
        let ePointer = 0;
        let i = 0;
        let index;

        // generate random indexes (x coordinate)
        do {
           if (ePointer >= e.length) {
               // get more 32 bytes entropy
               e = S.generateEntropy({hex:false});
               ePointer = 0;
           }

           index = e[ePointer] & index_mask;
           if ((shares[index] === undefined)&&(index !== 0)) {
               i++;
               shares[index] = BF([]);
               sharesIndexes.push(index)
           }

           ePointer++;
        } while (i !== total);


        e = S.generateEntropy({hex:false});
        ePointer = 0;

        let w;
        for (let b = 0; b < secret.length; b++) {
            let q = [secret[b]];

            for (let i = 0; i < threshold - 1; i++) {
                do {
                    if (ePointer >= e.length) {
                        ePointer = 0;
                        e = S.generateEntropy({hex:false});
                    }
                    w  = e[ePointer++];
                } while (q.includes(w));
                q.push(w);
            }

            for (let i of sharesIndexes)
                shares[i] = BC([shares[i], BF([S.__shamirFn(i, q)])]);

        }
        return shares;
    };

    S.__restore_secret = (shares) => {
      let secret = BF([]);
      let shareLength = null;
      let q = [];

      for (let i in shares) {
          i = parseInt(i);
          if ((i < 1) || (i > 255)) throw new Error("Invalid share index " + i);
          if (shareLength === null) shareLength = shares[i].length;
          if ((shareLength !== shares[i].length) || (shareLength === 0))  throw new Error("Invalid shares");
      }

      for (let i = 0; i < shareLength; i++) {
          let points = [];
          for (let z in shares) {
              z = parseInt(z);
              points.push([z, shares[z][i]])
          }
          secret = BC([secret, BF([S.__shamirInterpolation(points)])])
      }
      return secret;
    };

    S.__precompute_GF256_expLog(S);
};