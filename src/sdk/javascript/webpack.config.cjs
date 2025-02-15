const path = require('path');
const TerserPlugin = require('terser-webpack-plugin');
const webpack = require('webpack');

const config = {
  entry: './src/appmesh.js',
  experiments: { outputModule: true },
  output: {
    path: path.resolve(process.cwd(), 'dist'),
    filename: 'appmesh.esm.js',
    library: { type: 'module' },
    module: true,
    environment: { 
      module: true,
      dynamicImport: true
    }
  },
  target: ['web', 'es2015'],
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: { presets: ['@babel/preset-env'] }
        }
      }
    ]
  },
  optimization: {
    minimize: true,
    minimizer: [new TerserPlugin({ extractComments: false })]
  },
  resolve: {
    extensions: ['.js'],
    fallback: {
      fs: false,
      path: false,
      https: false,
      http: false,
      buffer: false
    }
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'production')
    })
  ]
};

module.exports = config;
