  const path = require('path');

  module.exports = {
    entry: './src/jsbtc.js',
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: 'jsbtc.js',
      library: 'jsbtc',
     libraryTarget: 'umd',
    },
    externals: {
      lodash: {
        commonjs: 'lodash',
        commonjs2: 'lodash',
        amd: 'lodash',
        root: '_',
      },
    },
  };