const path = require('path');
const TerserPlugin = require('terser-webpack-plugin');
const webpack = require('webpack');

const commonConfig = {
  entry: './src/appmesh.js',
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
    minimizer: [new TerserPlugin()]
  },
  resolve: {
    extensions: ['.js'],
    fallback: {
      buffer: require.resolve('buffer/'),
      https: require.resolve('https-browserify'),
      http: require.resolve('stream-http'),
      url: require.resolve('url/')
    }
  },
  plugins: [new webpack.ProvidePlugin({ Buffer: ['buffer', 'Buffer'] })]
};

module.exports = [
  // Node.js Build (Keep axios external)
  {
    ...commonConfig,
    target: 'node',
    output: {
      path: path.resolve(process.cwd(), 'dist'),
      filename: 'appmesh.node.js',
      library: { type: 'umd', export: 'default' },
      globalObject: 'this'
    },
    externals: { axios: 'axios', 'base-64': 'base-64' }
  },

  // Browser Build (Bundle axios)
  {
    ...commonConfig,
    target: 'web',
    output: {
      path: path.resolve(process.cwd(), 'dist'),
      filename: 'appmesh.browser.js',
      library: { type: 'umd', export: 'default' },
      globalObject: 'this'
    }
  },

  // UMD Build for CommonJS and ES Module (appmesh.js)
  {
    ...commonConfig,
    target: 'web',
    output: {
      path: path.resolve(process.cwd(), 'dist'),
      filename: 'appmesh.js',
      library: { type: 'umd', export: 'default' },
      globalObject: 'this'
    }
  },

  // ES Module Build (appmesh.esm.js)
  {
    ...commonConfig,
    target: 'web',
    output: {
      path: path.resolve(process.cwd(), 'dist'),
      filename: 'appmesh.esm.js',
      library: {
        type: 'module'
      },
      module: true,
      environment: {
        module: true
      }
    },
    experiments: {
      outputModule: true
    }
  }
];