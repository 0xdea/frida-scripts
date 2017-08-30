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

	// SSL pinning bypass: change retval, reimplementation technique

	var CertPinning = ObjC.classes.CertPinning;
	var getID = CertPinning["- getID:"];
	var getID_oldImpl = getID.implementation;

	getID.implementation = ObjC.implement(getID, function (handle, selector, arg1) {
		//return getID_oldImpl(handle, selector, arg1);
    		console.log("info: entered getID");
    		var retnew = ObjC.classes.NSString.stringWithString_("151f09ff42c55a4fcbae2246eb58f1d2f2168c0d");
		return retnew;
	});

} else {
 	send("error: Objective-C Runtime is not available!");
}
