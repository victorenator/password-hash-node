import {create} from './index.js';

if (process.argv.length < 3) {
    console.error('Usage: %s <password> [<schema>]', process.argv[1]);
    process.exit(1);
}

const res = await create(process.argv[2], process.argv[3]);
console.log(res);
