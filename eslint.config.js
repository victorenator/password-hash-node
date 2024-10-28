import js from '@eslint/js';
import globals from 'globals';

export default [
    {
        languageOptions: {
            sourceType: 'module',
            globals: {
                ... globals.node,
            }
        }
    },
    js.configs.recommended,
];
