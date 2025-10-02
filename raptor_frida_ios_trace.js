/*
 * raptor_frida_ios_trace.js - ObjC and Module tracer for iOS
 * Copyright (c) 2017-2025 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * "Life is not like water. Things in life don't necessarily 
 * flow over the shortest possible route."
 *                                  -- Haruki Murakami, 1Q84
 * 
 * Frida.re JS code to trace arbitrary ObjC methods and Module functions calls 
 * in an iOS app for debugging and reverse engineering. See https://www.frida.re/ 
 * and https://codeshare.frida.re/ for further information on this world-class
 * dynamic instrumentation toolkit.
 *
 * Example usage:
 * $ pipx install frida-tools
 * $ frida -U -f com.target.app -l raptor_frida_ios_trace.js
 *
 * Tested with:
 * Frida 17.3.2 on macOS 15.6.1 with iPhone 8 (iOS 16.5 + https://palera.in/)
 * 
 * Thanks:
 * @inode-, @federicodotta, @mrmacete, @dankluev
 * 
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 */

// Generic trace
// TODO: support the "swift" type
function trace(pattern)
{
	var type = (pattern.indexOf(" ") === -1) ? "module" : "objc";
	var res = new ApiResolver(type);
	var matches = res.enumerateMatches(pattern);
	var targets = uniqBy(matches, JSON.stringify);

	targets.forEach(function(target) {
		if (type === "objc")
			traceObjC(target.address, target.name);
		else if (type === "module")
			traceModule(target.address, target.name);
	});
}

// Remove duplicates from array
function uniqBy(array, key) 
{
	var seen = {};
	return array.filter(function(item) {
		var k = key(item);
		return seen.hasOwnProperty(k) ? false : (seen[k] = true);
	});
}

// Trace ObjC methods
function traceObjC(impl, name)
{
	console.log("Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			// Trace only the intended calls
			this.flag = 0;
			// if (ObjC.Object(args[2]).toString() === "1234567890abcdef1234567890abcdef12345678")
				this.flag = 1;

			if (this.flag) {
				console.warn("\n*** entered " + name);

				// Print full backtrace
				// console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
				//		.map(DebugSymbol.fromAddress).join("\n"));

				// Print caller
				console.log("\nCaller: " + DebugSymbol.fromAddress(this.returnAddress));

				// Print args
				if (name.indexOf(":") !== -1) {
					console.log();
					var par = name.split(":");
					par[0] = par[0].split(" ")[1];
					for (var i = 0; i < par.length - 1; i++)
						printArg(par[i] + ": ", args[i + 2]);
				}
			}
		},

		onLeave: function(retval) {

			if (this.flag) {
				// Print retval
				printArg("\nretval: ", retval);
				console.warn("\n*** exiting " + name);
			}
		}

	});
}

// Trace Module functions
function traceModule(impl, name)
{
	console.log("Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			// Trace only the intended calls
			this.flag = 0;
			// var filename = args[0].readCString();
			// if (filename.indexOf("Bundle") === -1 && filename.indexOf("Cache") === -1) // exclusion list
			// if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
				this.flag = 1;

			if (this.flag) {
				console.warn("\n*** entered " + name);

				// print backtrace
				console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
						.map(DebugSymbol.fromAddress).join("\n"));
			}
		},

		onLeave: function(retval) {

			if (this.flag) {
				// Print retval
				printArg("\nretval: ", retval);
				console.warn("\n*** exiting " + name);
			}
		}

	});
}

// Print helper
// TODO: implement a safe way to print ObjC objects and especially NSStrings/CStrings
function printArg(desc, arg)
{
	/*
	try {
		console.log(desc + ObjC.Object(arg));
	}
	catch(err) {
		console.log(desc + arg);
	}
	*/
	console.log(desc + arg);
}

// Usage examples
if (ObjC.available) {

	// trace("-[CredManager setPassword:]");
	// trace("*[CredManager *]");
	// trace("*[* *Password:*]");
	// trace("exports:libSystem.B.dylib!CCCrypt");
	// trace("exports:libSystem.B.dylib!open");
	// trace("exports:*!open*");
	
} else {
 	send("error: Objective-C Runtime is not available!");
}
