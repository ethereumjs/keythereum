"use strict";

var path = require("path");
var cp = require("child_process");
var gulp = require("gulp");
var del = require("del");
var keythereum = require("./");

gulp.task("clean", function (callback) {
  del([path.join("dist", "*.js")], callback);
});

gulp.task("lint", function (callback) {
  cp.exec("npm run lint", function (err, stdout) {
    if (err) if (stdout) process.stdout.write(stdout);
    callback(err);
  });
});

gulp.task("build", function (callback) {
  del([path.join("dist", "*.js")], function (err) {
    if (err) throw err;
    cp.exec("./node_modules/browserify/bin/cmd.js ./exports.js | ./node_modules/uglify-js/bin/uglifyjs > ./dist/keythereum.min.js", function (err, stdout) {
      if (err) throw err;
      if (stdout) process.stdout.write(stdout);
      cp.exec("./node_modules/browserify/bin/cmd.js ./exports.js > ./dist/keythereum.js", function (err, stdout) {
        if (err) throw err;
        if (stdout) process.stdout.write(stdout);
        callback();
      });
    });
  });
});

gulp.task("keygen", function (callback) {
  var dk = keythereum.create();
  var keyobj = keythereum.dump("testpass", dk.privateKey, dk.salt, dk.iv, null);
  keythereum.exportToFile(keyobj, null, function () {
    callback();
  });
});

gulp.task("default", ["lint", "build"]);
