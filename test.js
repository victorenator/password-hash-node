import {ok} from 'node:assert';
import test from 'node:test';
import {create, verify} from './index.js';

test('test PBKDF2/24/20000/24/sha256', async () => {
    const pw = 'thaimoRizieR3iexiil3oogo';
    const pwHash = await create(pw, 'PBKDF2/24/20000/24/sha256');
    const pwHash2 = await create(pw, 'PBKDF2/24/20000/24/sha256');
    ok(pwHash.startsWith('{PBKDF2/24/20000/24/sha256}'));
    ok(pwHash !== pwHash2);
    ok(verify(pw, pwHash));
});

test('test SSHA256/24', async () => {
    const pw = 'die1WioThoi0ietheeng0Pha';
    const pwHash = await create(pw, 'SSHA256/24');
    const pwHash2 = await create(pw, 'SSHA256/24');
    ok(pwHash.startsWith('{SSHA256/24}'));
    ok(pwHash !== pwHash2);
    ok(verify(pw, pwHash));
    ok(!verify('other', pwHash));
});

test('test SSHA', async () => {
    const pw = 'baK5eethahreecahsohmooh8';
    const pwHash = await create(pw, 'SSHA');
    const pwHash2 = await create(pw, 'SSHA');
    ok(pwHash.startsWith('{SSHA}'));
    ok(pwHash !== pwHash2);
    ok(verify(pw, pwHash));
    ok(!verify('other', pwHash));
});

test('test PLAIN', async () => {
    const pw = 'boojek6eu1aungiek0IH8iTh';
    const pwHash = await create(pw, 'PLAIN');
    const pwHash2 = await create(pw, 'PLAIN');
    ok(pwHash.startsWith('{PLAIN}'));
    ok(pwHash === pwHash2);
    ok(verify(pw, pwHash));
    ok(!verify('other', pwHash));
});
