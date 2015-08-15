"use strict";

var cp = require("child_process");
var gulp = require("gulp");
var del = require("del");

gulp.task("clean", function (callback) {
    del(["dist/keythereum.js"], callback);
});

gulp.task("build", function (callback) {
    cp.exec("./node_modules/browserify/bin/cmd.js ./exports.js | "+
            "./node_modules/uglify-js/bin/uglifyjs > ./dist/keythereum.js",
            function (err, stdout) {
        if (err) throw err;
        if (stdout) process.stdout.write(stdout);
        callback();
    });
});

gulp.task("keygen", function (callback) {
    var keythereum = require('./');
    var dk = keythereum.create();
    var keyobj = keythereum.dump("testpass", dk.privateKey, dk.salt, dk.iv, null);
    keythereum.exportToFile(keyobj, null, function () {
        callback();
    });
});

gulp.task("default", ["clean", "build"]);
