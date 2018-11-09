(window["webpackJsonp"] = window["webpackJsonp"] || []).push([[1],{

/***/ 181:
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "scrypt", function() { return scrypt; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "__wbindgen_throw", function() { return __wbindgen_throw; });
/* harmony import */ var _scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(182);
/* tslint:disable */


let cachedTextEncoder = new TextEncoder('utf-8');

let cachegetUint8Memory = null;
function getUint8Memory() {
    if (cachegetUint8Memory === null || cachegetUint8Memory.buffer !== _scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* memory */ "d"].buffer) {
        cachegetUint8Memory = new Uint8Array(_scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* memory */ "d"].buffer);
    }
    return cachegetUint8Memory;
}

function passStringToWasm(arg) {

    const buf = cachedTextEncoder.encode(arg);
    const ptr = _scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* __wbindgen_malloc */ "c"](buf.length);
    getUint8Memory().set(buf, ptr);
    return [ptr, buf.length];
}

let cachedTextDecoder = new TextDecoder('utf-8');

function getStringFromWasm(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
}

let cachedGlobalArgumentPtr = null;
function globalArgumentPtr() {
    if (cachedGlobalArgumentPtr === null) {
        cachedGlobalArgumentPtr = _scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* __wbindgen_global_argument_ptr */ "b"]();
    }
    return cachedGlobalArgumentPtr;
}

let cachegetUint32Memory = null;
function getUint32Memory() {
    if (cachegetUint32Memory === null || cachegetUint32Memory.buffer !== _scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* memory */ "d"].buffer) {
        cachegetUint32Memory = new Uint32Array(_scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* memory */ "d"].buffer);
    }
    return cachegetUint32Memory;
}
/**
* @param {string} arg0
* @param {string} arg1
* @param {number} arg2
* @param {number} arg3
* @param {number} arg4
* @param {number} arg5
* @returns {string}
*/
function scrypt(arg0, arg1, arg2, arg3, arg4, arg5) {
    const [ptr0, len0] = passStringToWasm(arg0);
    const [ptr1, len1] = passStringToWasm(arg1);
    const retptr = globalArgumentPtr();
    try {
        _scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* scrypt */ "e"](retptr, ptr0, len0, ptr1, len1, arg2, arg3, arg4, arg5);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        _scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* __wbindgen_free */ "a"](rustptr, rustlen * 1);
        return realRet;


    } finally {
        _scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* __wbindgen_free */ "a"](ptr0, len0 * 1);
        _scrypt_wasm_bg__WEBPACK_IMPORTED_MODULE_0__[/* __wbindgen_free */ "a"](ptr1, len1 * 1);

    }

}

function __wbindgen_throw(ptr, len) {
    throw new Error(getStringFromWasm(ptr, len));
}



/***/ }),

/***/ 182:
/***/ (function(module, exports, __webpack_require__) {

"use strict";
// Instantiate WebAssembly module
var wasmExports = __webpack_require__.w[module.i];

// export exports from WebAssembly module
module.exports = wasmExports;
// exec imports from WebAssembly module (for esm order)
/* harmony import */ var m0 = __webpack_require__(181);


// exec wasm module
wasmExports["f"]()

/***/ })

}]);