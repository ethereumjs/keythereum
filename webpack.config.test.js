const path = require("path");
const webpack = require("webpack");
const dist = path.resolve(__dirname, "test/browser");
module.exports = {
  entry: {
    bundle: "./test/keys.js"
  },
  output: {
    path: dist,
    filename: "[name].js"
  },
  node: {
    fs: "empty"
  },
  externals: {
    TextDecoder: "TextDecoder",
    TextEncoder: "TextEncoder"
  },
  plugins: []
};
