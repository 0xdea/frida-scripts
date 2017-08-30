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

// is stalker active?
var active = false;

// generic stalker
function stalk(pattern)
{
	var type = (pattern.indexOf(' ') === -1) ? 'module' : 'objc';
	var res = new ApiResolver(type);
	var matches = res.enumerateMatchesSync(pattern);
	var targets = uniqBy(matches, JSON.stringify);

	targets.forEach(function(target) {
		stalkFunction(target.address, target.name);
	});
}

// remove duplicates from array
function uniqBy(array, key) 
{
	var seen = {};
	return array.filter(function(item) {
		var k = key(item);
		return seen.hasOwnProperty(k) ? false : (seen[k] = true);
	});
}

// actual stalker function
function stalkFunction(impl, name)
{
	console.log("Stalking " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			// return if stalker is already active
			if (active)
				return;

			// initialize flag
			var flag = {};
			this.flag = flag;

			// activate stalker
			active = true;
			// console.warn("\n*** Stalker activated on " + name); // DEBUG

			Stalker.follow({

				events: {
					call:	true, 	// CALL instructions: yes please
					ret:	false, 	// RET instructions: no thanks
					exec:	false 	// all instructions: no thanks
				},

				// onReceive: function (events) { // TODO
					// Called with `events` containing a binary blob which is one or more
					// GumEvent structs.  See `gumevent.h` for the format. This is obviously a
					// terrible API that is subject to change once a better trade-off between
					// ease-of-use and performance has been found.
				// },

				onCallSummary: function (summary) {
					// Called with `summary` being a key-value mapping of call target to number
					// of calls, in the current time window. You would typically implement this
					// instead of `onReceive` for efficiency.
					console.log();
					Object.keys(summary).forEach(function (target) {
						console.log(name + " > " + DebugSymbol.fromAddress(ptr(target)).toString());
						flag[target] = true;
					});
				}

			});
		},

		onLeave: function(retval) {

			// return if no flag
			var flag = this.flag;
			if (flag === undefined)
				return;

			// deactivate stalker
			Stalker.unfollow();
			active = false;
			// console.warn("*** Stalker deactivated on " + name + "\n"); // DEBUG
		}

	});
}

// some examples
if (ObjC.available) {

	// stalk("*[OWSMessageSender *]"); // Signal
	// stalk("-[OWSMessageSender attemptToSendMessage*]"); // Signal
	// stalk("-[OWSMessageSender tag]"); // Signal
	// stalk("*[* *Password:*]");
	// stalk("exports:libSystem.B.dylib!open");
	// stalk("exports:*!open*");
	
} else {
 	send("error: Objective-C Runtime is not available!");
}
