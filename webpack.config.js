const path = require('path');
const TerserPlugin = require('terser-webpack-plugin');
const nodeEnv = process.env.NODE_ENV

const jsbtc_web = {
    mode: "production",
    target: 'web',
    context: path.resolve(__dirname, "."),
    node: {
        fs: 'empty'
    },
    entry: './src/jsbtc.js',
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'jsbtc.js',
        library: 'jsbtc',
        libraryTarget: 'var',
    },
    optimization: {
        sideEffects: true,
        minimize: true,
            minimizer: [
            new TerserPlugin({
                extractComments: false,
                terserOptions: {
                    output: {
                        comments: false,
                    },
                },
            }),
        ],
    },
    module: {
        noParse: /crypto/,
    },
    performance: { hints: false }
};

module.exports = [jsbtc_web];

