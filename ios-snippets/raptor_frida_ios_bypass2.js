/*
 * raptor_frida_ios_*.js - Frida script snippets for iOS
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS script snippets for iOS/ObjC instrumentation.
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
 * # frida -U -f com.xxx.yyy -l raptor_frida_ios.js --no-pause
 */

if (ObjC.available) {

	// Jailbreak detection bypass: change retval, onLeave technique

	var hook = ObjC.classes.JailbreakChecks["- isJailbroken"];

	Interceptor.attach(hook.implementation, {

		onLeave: function(retval) {
			console.log("info: exiting isJailbroken");

			// read retval
			var obj = ObjC.Object(retval);
			console.log("retval type:", obj.$class, obj.$className);
			console.log("old retval value:", obj.toString());

			// change retval
			var retnew = ObjC.classes.NSString.stringWithString_("false");
			retval.replace(retnew);
			console.log("new retval value:", obj.toString());
		} 
	});

} else {
 	send("error: Objective-C Runtime is not available!");
}
