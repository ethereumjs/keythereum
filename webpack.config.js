const path = require("path");
const webpack = require("webpack");
const dist = path.resolve(__dirname, "dist");
var UnminifiedWebpackPlugin = require("unminified-webpack-plugin");
module.exports = {
  entry: {
    keythereum: "./exports.js"
  },
  output: {
    path: dist,
    filename: "[name].min.js"
  },
  node: {
    fs: "empty"
  },
  externals: {
    TextDecoder: "TextDecoder",
    TextEncoder: "TextEncoder"
  },
  plugins: [new UnminifiedWebpackPlugin()]
};
