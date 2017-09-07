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

// find loaded classes that match a pattern (async)
function findClass(pattern)
{
	console.warn("\n*** finding all classes that match pattern: " + pattern + "\n");

	Java.enumerateLoadedClasses({
		onMatch: function(aClass) {
			if (aClass.match(pattern))
				console.log(aClass);
		},
		onComplete: function() {}
	});
}

// usage examples
setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {

		//findClass();		// print all loaded classes
		//findClass("Root");	// print all classes that match a string
		//findClass(/root/i);	// print all classes that match a regex (e.g., case insensitive)

	});   

}, 0);
