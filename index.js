const crypto = require('crypto');

async function create(password, schema = 'PBKDF2/24/20000/24/sha256') {
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
            hash = new Buffer(password);
            break;

        default:
            throw new Error('Invalid schema');
    }

    return `{${schema}}${hash.toString('base64')}`;
};

function verify(password, passwordHash) {
    const p = passwordHash.indexOf('}');
    if (passwordHash.charAt(0) !== '{' || p === -1) {
        throw new Error('Invalid hash');
    }

    const schema = passwordHash.slice(1, p);
    const schemaParts = schema.split('/');
    const hash = new Buffer(passwordHash.slice(p + 1), 'base64');

    switch (schemaParts[0]) {
        case 'PBKDF2':
            return verifyPBKDF2(password, hash, Number(schemaParts[1]), Number(schemaParts[2]), Number(schemaParts[3]), schemaParts[4]);
            break;

        case 'SSHA256':
            return verifySSHA256(password, hash, Number(schemaParts[1]));
            break;

        case 'SSHA':
            return verifySSHA(password, hash);
            break;

        case 'PLAIN':
            return new Buffer(password).equals(hash);
            break;

        default:
            throw new Error('Invalid schema');
    }
};

async function createPBKDF2(password, saltSize, iterations, hashSize, digestAlgo) {
    const salt = crypto.randomBytes(saltSize);

    const digest = await digestPBKDF2(password, salt, iterations, hashSize, digestAlgo);

    const hash = new Buffer(digest.length + salt.length);
    digest.copy(hash);
    salt.copy(hash, digest.length);

    return hash;
}

async function verifyPBKDF2(password, hash, saltSize, iterations, hashSize, digestAlgo) {
    const digestSize = hash.length - saltSize;
    const digest = await digestPBKDF2(password, hash.slice(digestSize), iterations, hashSize, digestAlgo);
    return digest.compare(hash, 0, digestSize) === 0;
}

function digestPBKDF2(password, salt, iterations, hashSize, digestAlgo) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, iterations, hashSize, digestAlgo, (error, key) => {
            if (error) {
                reject(error);

            } else {
                resolve(key);
            }
        });
    });
}

function createSSHA256(password, saltSize) {
    const salt = crypto.randomBytes(saltSize);

    const digest = digestSSHA256(password, salt);

    const hash = new Buffer(digest.length + salt.length);
    digest.copy(hash);
    salt.copy(hash, digest.length);

    return hash;
}

function verifySSHA256(password, hash, saltSize) {
    const digestSize = hash.length - saltSize;
    return digestSSHA256(password, hash.slice(digestSize)).compare(hash, 0, digestSize) === 0;
}

function digestSSHA256(password, salt) {
    const hash = crypto.createHash('sha256');
    hash.update(password);
    hash.update(salt);
    return hash.digest();
}

function createSSHA(password) {
    const salt = crypto.randomBytes(8);

    const digest = digestSSHA(password, salt);

    const hash = new Buffer(digest.length + salt.length);
    digest.copy(hash);
    salt.copy(hash, digest.length);

    return hash;
}

function verifySSHA(password, hash) {
    return digestSSHA(password, hash.slice(20)).compare(hash, 0, 20) === 0;
};

function digestSSHA(password, salt) {
    let hash = crypto.createHash('sha1');
    hash.update(password);
    hash.update(salt);
    return hash.digest();
}

exports.create = create;
exports.verify = verify;

if (require.main === module) {
    if (process.argv.length < 3) {
        console.error('Usage: %s <password> [<schema>]', process.argv[1]);
        process.exit(1);
    }

    console.log(create(process.argv[2], process.argv[3]));
}
