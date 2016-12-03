# Getting Started
## Install
```bash
npm install password-hash-node
```

## Use
```javascript
const passwordHash = require('password-hash-node');

const hash = await passwordHash.create('password', 'SSHA');

const valid = await passwordHash.verify('password', hash);
```

# Schemas
- PBKDF2/$salt-size/$iterations/$hash-size/$digest-algorithm eg. PBKDF2/24/20000/24/sha256
- SSHA256/$salt-size
- SSHA
- PLAIN

# License
Copyright ⓒ 2016 Viktar Vaŭčkievič

