/*
 * raptor_frida_linux_trace.js - Function tracer for Linux
 * Copyright (c) 2025 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * "Life is not like water. Things in life don't necessarily 
 * flow over the shortest possible route."
 *                                  -- Haruki Murakami, 1Q84
 *
 * Frida.re JS code to trace arbitrary function calls in a Linux ELF binary
 * for debugging and reverse engineering. See https://www.frida.re/ and
 * https://codeshare.frida.re/ for further information on this world-class
 * dynamic instrumentation toolkit.
 *
 * Example usage:
 * $ pipx install frida-tools
 * $ frida -f hello-vuln -l raptor_frida_linux_trace.js
 * 
 * Tested with:
 * Frida 17.2.1 on Ubuntu 24.0
 *
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 */

// Generic trace
function trace(pattern)
{
	var type = (pattern.toString().indexOf("!") === -1) ? "function" : "module";

	// Trace exported and imported functions of shared libraries
	if (type === "module") {
		var res = new ApiResolver("module");
		var matches = res.enumerateMatches(pattern);
		var targets = uniqBy(matches, JSON.stringify);

		targets.forEach(function(target) {
			traceFunction(target.address, target.name);
		});

	// Trace functions in the target binary
	} else if (type === "function") {
		var targets = []

		for (const f of DebugSymbol.findFunctionsMatching(pattern)) {
			targets.push(DebugSymbol.fromAddress(ptr(f)));
		}
		targets.forEach(function(target) {
			traceFunction(target.address, target.name);
		});
	}
}

// Trace a function call
function traceFunction(impl, name)
{
	console.log("Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {
			// Trace only the intended calls
      this.flag = 0;
      //if (args[0].readUtf8String().match("AAA"))
        this.flag = 1;

			if (this.flag) {
				console.warn("\n*** entered " + name);

				// Print full backtrace
				console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
					.map(DebugSymbol.fromAddress).join("\n"));

				// Print caller
				//console.log("\nCaller: " + DebugSymbol.fromAddress(this.returnAddress))

				// Print args (see https://frida.re/docs/javascript-api/#interceptor)
				//console.log();
				//console.log("arg1: " + args[0]);
				//console.log("arg2: " + args[1]);
				//console.log("arg3: " + args[2].readUtf8String());
				//console.log("arg4: " + args[3].readUtf8String());
			}
		},

		onLeave: function(retval) {
			if (this.flag) {
				// Print retval
				console.log("\nretval: " + retval);

				console.warn("\n*** exiting " + name);
			}
		}

	});
}

// Remove duplicates from an array
function uniqBy(array, key)
{
	var seen = {};
	return array.filter(function(item) {
		var k = key(item);
 		return seen.hasOwnProperty(k) ? false : (seen[k] = true);
 	});
}

// Usage examples

// Trace all imports
//trace("imports:*!*");

// Trace potential command injection sinks
//trace("imports:*!system");
//trace("imports:*!popen");

// Trace an export
//trace("exports:*!snprintf");

// Trace a function that matches a glob pattern
//trace("main")
