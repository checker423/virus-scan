self.onmessage = async function(e) {
    const { file, type } = e.data;
    
    if (type === 'PROCESS_FILE') {
        try {
            // Process entire file for accurate hashes
            const CHUNK_SIZE = 1024 * 1024 * 2; // 2MB chunks
            const fileSize = file.size;
            let offset = 0;
            
            // Read entire file for accurate hashing
            const fileBuffer = await file.arrayBuffer();
            const u8 = new Uint8Array(fileBuffer);
            
            // Calculate hashes from entire file
            const sha256Buffer = await crypto.subtle.digest('SHA-256', fileBuffer);
            const sha1Buffer = await crypto.subtle.digest('SHA-1', fileBuffer);
            const md5Hash = md5(u8); // Custom MD5 implementation
            
            const sha256Hash = Array.from(new Uint8Array(sha256Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
            const sha1Hash = Array.from(new Uint8Array(sha1Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
            
            // Chunked processing for entropy and strings
            let totalEntropySum = 0;
            let segments = [];
            let extractedStrings = [];
            let chunkCount = 0;
            
            while (offset < fileSize && chunkCount < 16) { // limit to 16 chunks to avoid UI hang
                const chunk = file.slice(offset, offset + CHUNK_SIZE);
                const arrayBuffer = await chunk.arrayBuffer();
                const chunkU8 = new Uint8Array(arrayBuffer);
                
                // Entropy of chunk
                const ent = calculateEntropy(chunkU8);
                totalEntropySum += ent;
                segments.push(ent);
                
                // Extract strings from chunk (limit size)
                if (extractedStrings.length < 500) {
                    const strs = extractStrings(chunkU8);
                    extractedStrings = extractedStrings.concat(strs);
                }
                
                offset += CHUNK_SIZE;
                chunkCount++;
                
                // Report progress
                self.postMessage({ type: 'PROGRESS', progress: Math.floor((offset / fileSize) * 100) });
            }
            
            const avgEntropy = totalEntropySum / chunkCount;
            
            self.postMessage({
                type: 'COMPLETE',
                results: {
                    sha256: sha256Hash,
                    sha1: sha1Hash,
                    md5: md5Hash,
                    entropy: avgEntropy,
                    entropySegments: segments,
                    strings: extractedStrings.slice(0, 500), // Limit array size for memory
                    headerBytes: new Uint8Array(await file.slice(0, 48).arrayBuffer())
                }
            });
            
        } catch (error) {
            self.postMessage({ type: 'ERROR', error: error.message });
        }
    }
};

// Simple MD5 implementation
function md5(array) {
    // MD5 implementation
    function rotateLeft(lValue, iShiftBits) {
        return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
    }
    
    function addUnsigned(lX, lY) {
        const lX4 = (lX & 0x40000000);
        const lY4 = (lY & 0x40000000);
        const lX8 = (lX & 0x80000000);
        const lY8 = (lY & 0x80000000);
        const lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
        if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
        if (lX4 | lY4) {
            if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
            else return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
        } else return (lResult ^ lX8 ^ lY8);
    }
    
    function f(x, y, z) { return (x & y) | ((~x) & z); }
    function g(x, y, z) { return (x & z) | (y & (~z)); }
    function h(x, y, z) { return x ^ y ^ z; }
    function i(x, y, z) { return y ^ (x | (~z)); }
    
    function ff(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(f(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    
    function gg(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(g(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    
    function hh(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(h(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    
    function ii(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(i(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    
    function convertToWordArray(array) {
        let lWordCount;
        const lMessageLength = array.length;
        const lNumberOfWords_temp1 = lMessageLength + 8;
        const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
        const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
        const lWordArray = Array(lNumberOfWords - 1);
        let lBytePosition = 0;
        let lByteCount = 0;
        while (lByteCount < lMessageLength) {
            lWordCount = (lByteCount - (lByteCount % 4)) / 4;
            lBytePosition = (lByteCount % 4) * 8;
            lWordArray[lWordCount] = (lWordArray[lWordCount] | (array[lByteCount] << lBytePosition));
            lByteCount++;
        }
        lWordCount = (lByteCount - (lByteCount % 4)) / 4;
        lBytePosition = (lByteCount % 4) * 8;
        lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
        lWordArray[lNumberOfWords - 2] = lMessageLength * 8;
        return lWordArray;
    }
    
    function wordToHex(lValue) {
        let wordToHexValue = '', wordToHexValue_temp = '', lByte, lCount;
        for (lCount = 0; lCount <= 3; lCount++) {
            lByte = (lValue >>> (lCount * 8)) & 255;
            wordToHexValue_temp = '0' + lByte.toString(16);
            wordToHexValue = wordToHexValue + wordToHexValue_temp.substr(wordToHexValue_temp.length - 2, 2);
        }
        return wordToHexValue;
    }
    
    const x = convertToWordArray(array);
    let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
    
    for (let k = 0; k < x.length; k += 16) {
        const AA = a, BB = b, CC = c, DD = d;
        a = ff(a, b, c, d, x[k + 0], 7, 0xD76AA478);
        d = ff(d, a, b, c, x[k + 1], 12, 0xE8C7B756);
        c = ff(c, d, a, b, x[k + 2], 17, 0x242070DB);
        b = ff(b, c, d, a, x[k + 3], 22, 0xC1BDCEEE);
        a = ff(a, b, c, d, x[k + 4], 7, 0xF57C0FAF);
        d = ff(d, a, b, c, x[k + 5], 12, 0x4787C62A);
        c = ff(c, d, a, b, x[k + 6], 17, 0xA8304613);
        b = ff(b, c, d, a, x[k + 7], 22, 0xFD469501);
        a = ff(a, b, c, d, x[k + 8], 7, 0x698098D8);
        d = ff(d, a, b, c, x[k + 9], 12, 0x8B44F7AF);
        c = ff(c, d, a, b, x[k + 10], 17, 0xFFFF5BB1);
        b = ff(b, c, d, a, x[k + 11], 22, 0x895CD7BE);
        a = ff(a, b, c, d, x[k + 12], 7, 0x6B901122);
        d = ff(d, a, b, c, x[k + 13], 12, 0xFD987193);
        c = ff(c, d, a, b, x[k + 14], 17, 0xA679438E);
        b = ff(b, c, d, a, x[k + 15], 22, 0x49B40821);
        a = gg(a, b, c, d, x[k + 1], 5, 0xF61E2562);
        d = gg(d, a, b, c, x[k + 6], 9, 0xC040B340);
        c = gg(c, d, a, b, x[k + 11], 14, 0x265E5A51);
        b = gg(b, c, d, a, x[k + 0], 20, 0xE9B6C7AA);
        a = gg(a, b, c, d, x[k + 5], 5, 0xD62F105D);
        d = gg(d, a, b, c, x[k + 10], 9, 0x02441453);
        c = gg(c, d, a, b, x[k + 15], 14, 0xD8A1E681);
        b = gg(b, c, d, a, x[k + 4], 20, 0xE7D3FBC8);
        a = gg(a, b, c, d, x[k + 9], 5, 0x21E1CDE6);
        d = gg(d, a, b, c, x[k + 14], 9, 0xC33707D6);
        c = gg(c, d, a, b, x[k + 3], 14, 0xF4D50D87);
        b = gg(b, c, d, a, x[k + 8], 20, 0x455A14ED);
        a = gg(a, b, c, d, x[k + 13], 5, 0xA9E3E905);
        d = gg(d, a, b, c, x[k + 2], 9, 0xFCEFA3F8);
        c = gg(c, d, a, b, x[k + 7], 14, 0x676F02D9);
        b = gg(b, c, d, a, x[k + 12], 20, 0x8D2A4C8A);
        a = hh(a, b, c, d, x[k + 5], 4, 0xFFFA3942);
        d = hh(d, a, b, c, x[k + 8], 11, 0x8771F681);
        c = hh(c, d, a, b, x[k + 11], 16, 0x6D9D6122);
        b = hh(b, c, d, a, x[k + 14], 23, 0xFDE5380C);
        a = hh(a, b, c, d, x[k + 1], 4, 0xA4BEEA44);
        d = hh(d, a, b, c, x[k + 4], 11, 0x4BDECFA9);
        c = hh(c, d, a, b, x[k + 7], 16, 0xF6BB4B60);
        b = hh(b, c, d, a, x[k + 10], 23, 0xBEBFBC70);
        a = hh(a, b, c, d, x[k + 13], 4, 0x289B7EC6);
        d = hh(d, a, b, c, x[k + 0], 11, 0xEAA127FA);
        c = hh(c, d, a, b, x[k + 3], 16, 0xD4EF3085);
        b = hh(b, c, d, a, x[k + 6], 23, 0x04881D05);
        a = hh(a, b, c, d, x[k + 9], 4, 0xD9D4D039);
        d = hh(d, a, b, c, x[k + 12], 11, 0xE6DB99E5);
        c = hh(c, d, a, b, x[k + 15], 16, 0x1FA27CF8);
        b = hh(b, c, d, a, x[k + 2], 23, 0xC4AC5665);
        a = ii(a, b, c, d, x[k + 0], 6, 0xF4292244);
        d = ii(d, a, b, c, x[k + 7], 10, 0x432AFF97);
        c = ii(c, d, a, b, x[k + 14], 15, 0xAB9423A7);
        b = ii(b, c, d, a, x[k + 5], 21, 0xFC93A039);
        a = ii(a, b, c, d, x[k + 12], 6, 0x655B59C3);
        d = ii(d, a, b, c, x[k + 3], 10, 0x8F0CCC92);
        c = ii(c, d, a, b, x[k + 10], 15, 0xFFEFF47D);
        b = ii(b, c, d, a, x[k + 1], 21, 0x85845DD1);
        a = ii(a, b, c, d, x[k + 8], 6, 0x6FA87E4F);
        d = ii(d, a, b, c, x[k + 15], 10, 0xFE2CE6E0);
        c = ii(c, d, a, b, x[k + 6], 15, 0xA3014314);
        b = ii(b, c, d, a, x[k + 13], 21, 0x4E0811A1);
        a = ii(a, b, c, d, x[k + 4], 6, 0xF7537E82);
        d = ii(d, a, b, c, x[k + 11], 10, 0xBD3AF235);
        c = ii(c, d, a, b, x[k + 2], 15, 0x2AD7D2BB);
        b = ii(b, c, d, a, x[k + 9], 21, 0xEB86D391);
        a = addUnsigned(a, AA);
        b = addUnsigned(b, BB);
        c = addUnsigned(c, CC);
        d = addUnsigned(d, DD);
    }
    
    return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

function calculateEntropy(byteArray) {
    const len = byteArray.length;
    if (len === 0) return 0;
    const frequencies = new Array(256).fill(0);
    for (let i = 0; i < len; i++) {
        frequencies[byteArray[i]]++;
    }
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            const p = frequencies[i] / len;
            entropy -= p * Math.log2(p);
        }
    }
    return entropy;
}

function extractStrings(byteArray) {
    const stringsList = [];
    let currentString = '';
    const minLength = 5;
    const maxScanBytes = Math.min(byteArray.length, 1000000);
    
    for (let i = 0; i < maxScanBytes; i++) {
        const char = byteArray[i];
        if (char >= 32 && char <= 126) {
            currentString += String.fromCharCode(char);
        } else {
            if (currentString.length >= minLength) {
                stringsList.push(currentString);
                if (stringsList.length >= 100) break; // Limit per chunk
            }
            currentString = '';
        }
    }
    return stringsList;
}
