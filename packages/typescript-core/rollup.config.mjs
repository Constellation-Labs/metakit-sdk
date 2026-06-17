import resolve from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';

const external = (id) =>
  /^@noble\/|^bs58|^canonicalize|^@constellation-network\//.test(id);

const plugins = [
  resolve(),
  typescript({ tsconfig: './tsconfig.json' }),
];

const entries = [
  { input: 'src/index.ts', cjs: 'dist/cjs/index.js', esm: 'dist/esm/index.js' },
];

export default entries.map(({ input, cjs, esm }) => ({
  input,
  output: [
    { file: cjs, format: 'cjs', sourcemap: true, exports: 'named', interop: 'auto' },
    { file: esm, format: 'es', sourcemap: true },
  ],
  external,
  plugins,
}));
