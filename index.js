import {createHash, pbkdf2, randomBytes, timingSafeEqual} from 'node:crypto';

/**
 * Created password hash
 * @param {String} password
 * @param {String} [schema='PBKDF2/24/20000/24/sha256']
 */
export async function create(password, schema = 'PBKDF2/24/20000/24/sha256') {
    const schemaParts = schema.split('/');
    let hash;
    switch (schemaParts[0]) {
        case 'PBKDF2':
            hash = await createPBKDF2(password, Number(schemaParts[1]), Number(schemaParts[2]), Number(schemaParts[3]), schemaParts[4]);
            break;

        case 'SSHA256':
            hash = createSSHA256(password, Number(schemaParts[1]));
            break;

        case 'SSHA':
            hash = createSSHA(password);
            break;

        case 'PLAIN':
            hash = Buffer.from(password);
            break;

        default:
            throw new Error('Invalid schema');
    }

    return `{${schema}}${hash.toString('base64')}`;
}

/**
 * Verifies password
 * @param {String} password
 * @param {String} passwordHash
 * @returns {Promise<Boolean>}
 */
export async function verify(password, passwordHash) {
    const p = passwordHash.indexOf('}');
    if (passwordHash.charAt(0) !== '{' || p === -1) {
        throw new Error('Invalid hash');
    }

    const schema = passwordHash.slice(1, p);
    const schemaParts = schema.split('/');
    const hash = Buffer.from(passwordHash.slice(p + 1), 'base64');

    switch (schemaParts[0]) {
        case 'PBKDF2':
            return await verifyPBKDF2(password, hash, Number(schemaParts[1]), Number(schemaParts[2]), Number(schemaParts[3]), schemaParts[4]);

        case 'SSHA256':
            return verifySSHA256(password, hash, Number(schemaParts[1]));

        case 'SSHA':
            return verifySSHA(password, hash);

        case 'PLAIN':
            return Buffer.from(password).equals(hash);

        default:
            throw new Error('Invalid schema');
    }
}

/**
 * @param {String | Uint8Array} password
 * @param {Number} saltSize
 * @param {Number} iterations
 * @param {Number} hashSize
 * @param {String} digestAlgo
 */
async function createPBKDF2(password, saltSize, iterations, hashSize, digestAlgo) {
    const salt = randomBytes(saltSize);

    const digest = await digestPBKDF2(password, salt, iterations, hashSize, digestAlgo);

    const hash = Buffer.alloc(digest.length + salt.length);
    digest.copy(hash);
    salt.copy(hash, digest.length);

    return hash;
}

/**
 * @param {String | Uint8Array} password
 * @param {Uint8Array} hash
 * @param {Number} saltSize
 * @param {Number} iterations
 * @param {Number} hashSize
 * @param {String} digestAlgo
 */
async function verifyPBKDF2(password, hash, saltSize, iterations, hashSize, digestAlgo) {
    const digestSize = hash.length - saltSize;
    const digest = await digestPBKDF2(password, hash.slice(digestSize), iterations, hashSize, digestAlgo);
    return timingSafeEqual(digest, hash.slice(0, digestSize));
}

/**
 * @param {String | Uint8Array} password
 * @param {Uint8Array} salt
 * @param {Number} iterations
 * @param {Number} hashSize
 * @param {String} digestAlgo
 * @returns {Promise<Buffer>}
 */
function digestPBKDF2(password, salt, iterations, hashSize, digestAlgo) {
    return new Promise((resolve, reject) => {
        pbkdf2(password, salt, iterations, hashSize, digestAlgo, (error, key) => {
            if (error) {
                reject(error);

            } else {
                resolve(key);
            }
        });
    });
}

/**
 * @param {String | Uint8Array} password
 * @param {Number} saltSize
 * @returns {Buffer}
 */
function createSSHA256(password, saltSize) {
    const salt = randomBytes(saltSize);

    const digest = digestSSHA256(password, salt);

    const hash = Buffer.alloc(digest.length + salt.length);
    digest.copy(hash);
    salt.copy(hash, digest.length);

    return hash;
}

/**
 * @param {String | Uint8Array} password
 * @param {Uint8Array} hash
 * @param {Number} saltSize
 * @returns {Boolean}
 */
function verifySSHA256(password, hash, saltSize) {
    const digestSize = hash.length - saltSize;
    const digest = digestSSHA256(password, hash.slice(digestSize));
    return timingSafeEqual(digest, hash.slice(0, digestSize));
}

/**
 * @param {String | Uint8Array} password
 * @param {Uint8Array} salt
 * @returns {Buffer}
 */
function digestSSHA256(password, salt) {
    const hash = createHash('sha256');
    hash.update(password);
    hash.update(salt);
    return hash.digest();
}

/**
 * @param {String | Uint8Array} password
 * @returns {Buffer}
 */
function createSSHA(password) {
    const salt = randomBytes(8);

    const digest = digestSSHA(password, salt);

    const hash = Buffer.alloc(digest.length + salt.length);
    digest.copy(hash);
    salt.copy(hash, digest.length);

    return hash;
}

/**
 * @param {String | Uint8Array} password
 * @param {Uint8Array} hash
 */
function verifySSHA(password, hash) {
    const digest = digestSSHA(password, hash.slice(20));
    return timingSafeEqual(digest, hash.slice(0, 20));
}

/**
 * @param {String | Uint8Array} password
 * @param {Uint8Array} salt
 * @returns {Buffer}
 */
function digestSSHA(password, salt) {
    let hash = createHash('sha1');
    hash.update(password);
    hash.update(salt);
    return hash.digest();
}
