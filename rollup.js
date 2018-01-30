const rollup = require('rollup').rollup;
const async = require('rollup-plugin-async');
const nodent = require('rollup-plugin-nodent');
const commonjs =  require('rollup-plugin-commonjs');
const resolve =  require('rollup-plugin-node-resolve');
const babel =  require('rollup-plugin-babel');

// rollup({
//   input: './src/index.js',
//   output: {
//     file: 'dist/openpgpjsAA',
//     format: 'cjs'
//   },
//   plugins: [
//     nodent(),
//     commonjs({
//       'src/compression/rawinflate.min.js': [ 'rawinflate' ],
//       'src/compression/rawdeflate.min.js': [ 'rawdeflate' ],
//       'src/compression/zlib.min.js': [ 'zlib' ]
//     })
//   ]
// })
// .then((...arg) => {
//   console.log(arg)
// })
// .catch((e) => console.error(e))




async function build(input, output) {
  try {
    // create a bundle
    const bundle = await rollup({
      input,
      plugins: [
        nodent(),
        babel(),
        commonjs({
          'src/compression/rawinflate.min.js': [ 'rawinflate' ],
          'src/compression/rawdeflate.min.js': [ 'rawdeflate' ],
          'src/compression/zlib.min.js': [ 'zlib' ]
        })
      ],
      external: ['rawinflate', 'rawdeflate', 'zlib', 'crypto', 'buffer', 'node-localstorage', 'node-fetch', 'asn1.js']
    });

    const outputCfg = {
      name: output,
      file: `dist/${output}.cjs.js`,
      format: 'cjs'
    };

    // generate code and a sourcemap
    const { code, map } = await bundle.generate(outputCfg);

    // or write the bundle to disk
    await bundle.write(outputCfg);
  } catch(e) {
    console.error(e);
  }
}

build('./src/index.js', 'openpgp');
build('./src/worker/worker.js', 'openpgp.worker');