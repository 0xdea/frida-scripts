/*
 * raptor_frida_android_*.js - Frida snippets for Android
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS script snippets for Android instrumentation.
 * See https://www.frida.re/ and https://codeshare.frida.re/
 * for further information on this powerful tool.
 *
 * "We want to help others achieve interop through reverse
 * engineering" -- @oleavr
 *
 * Many thanks to Maurizio Agazzini <inode@wayreth.eu.org>
 * and Federico Dotta <federico.dotta@mediaservice.net>.
 *
 * Example usage:
 * # frida -U -f com.xxx.yyy -l raptor_frida_android.js --no-pause
 */

setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {

		// Debug some methods

		var CryptoUtils = Java.use("com.target.app.CryptoUtils");
		console.log("info: hooking class CryptoUtils");
		var PrefUtils = Java.use("com.target.app.PrefUtils");
		console.log("info: hooking class PrefUtils");

		CryptoUtils.decrypt.overload("java.lang.String").implementation = function(arg0) {
			console.warn("\n*** entered CryptoUtils.decrypt(java.lang.String arg0)");
			var retval = this.decrypt.overload("java.lang.String").call(this, arg0);
			console.log("\narg0: " + arg0);
			console.log("\nretval: " + retval);
			console.warn("\n*** exiting CryptoUtils.decrypt(java.lang.String arg0)");
			return retval;
		}

		CryptoUtils.decrypt.overload("java.lang.String", "java.lang.String").implementation = function(arg0, arg1) {
			console.warn("\n*** entered CryptoUtils.decrypt(java.lang.String arg0, java.lang.String arg1)");
			var retval = this.decrypt.overload("java.lang.String", "java.lang.String").call(this, arg0, arg1);
			console.log("\narg0: " + arg0);
			console.log("arg1: " + arg1);
			console.log("\nretval: " + retval);
			console.warn("\n*** exiting CryptoUtils.decrypt(java.lang.String arg0, java.lang.String arg1)");
			return retval;
		}

		// overload not really necessary here
		CryptoUtils.genIv.overload().implementation = function() {
			console.warn("\n*** entered CryptoUtils.genIv()");
			var retval = this.genIv.overload().call(this);
			console.log("\nretval: " + retval);
			console.warn("\n*** exiting CryptoUtils.genIv()");
			// XXX print IvParameterSpec | javax.crypto.spec.IvParameterSpec
			return retval;
		}

		// overload not really necessary here
		PrefUtils.saveUser.overload("java.util.List").implementation = function(arg0) {
			console.warn("\n*** entered PrefUtils.saveUser(java.util.List arg0)");
			var retval = this.saveUser.overload("java.util.List").call(this, arg0);
			console.log("\narg0: " + arg0);
			console.log("\nretval: " + retval);
			console.warn("\n*** exiting PrefUtils.saveUser(java.util.List arg0)");
			return retval;
		}

	});   

}, 0);
