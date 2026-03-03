import resolve from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';

const external = (id) =>
  /^@noble\/|^bs58|^canonicalize/.test(id);

const plugins = [
  resolve(),
  typescript({ tsconfig: './tsconfig.json' }),
];

const entries = [
  { input: 'src/index.ts', cjs: 'dist/cjs/index.js', esm: 'dist/esm/index.js' },
  { input: 'src/network/index.ts', cjs: 'dist/cjs/network/index.js', esm: 'dist/esm/network/index.js' },
  { input: 'src/json-logic/index.ts', cjs: 'dist/cjs/json-logic/index.js', esm: 'dist/esm/json-logic/index.js' },
];

export default entries.map(({ input, cjs, esm }) => ({
  input,
  output: [
    { file: cjs, format: 'cjs', sourcemap: true, exports: 'named' },
    { file: esm, format: 'es', sourcemap: true },
  ],
  external,
  plugins,
}));
