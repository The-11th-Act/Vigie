// ESLint 9 "flat" configuration; `npm run lint` reads it. It replaces
// .eslintrc.cjs (ESLint 8, no longer maintained) with the same rules.
import js from '@eslint/js'
import prettier from 'eslint-config-prettier/flat'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import globals from 'globals'

export default [
  { ignores: ['dist/**', 'node_modules/**'] },
  js.configs.recommended,
  react.configs.flat.recommended,
  react.configs.flat['jsx-runtime'],
  reactHooks.configs.flat.recommended,
  {
    // ESLint 9 lints .js/.mjs/.cjs alone by default: without this, every
    // component (.jsx) would be skipped and the lint would pass, silently.
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.node },
    },
    settings: { react: { version: 'detect' } },
    rules: {
      // Props are validated by the API contract and the tests rather than by
      // PropTypes, which this codebase does not use anywhere.
      'react/prop-types': 'off',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['**/*.test.jsx', '**/*.test.js', 'src/test/**'],
    languageOptions: {
      globals: {
        describe: 'readonly',
        it: 'readonly',
        expect: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        vi: 'readonly',
      },
    },
  },
  // Last, so formatting rules never fight Prettier.
  prettier,
]
