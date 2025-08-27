/*
 * raptor_frida_linux_enum.js - Module/function enumerator
 * Copyright (c) 2025 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * "For all is like an ocean, all flows and connects; 
 * touch it in one place and it echoes at the other end of the world."
 *                        -- Fyodor Dostoevsky, The Brothers Karamazov
 *
 * Frida.re JS code to enumerate modules and functions present in a Linux ELF
 * binary. See https://www.frida.re/ and https://codeshare.frida.re/ for
 * further information on this world-class dynamic instrumentation toolkit.
 *
 * Example usage:
 * $ frida -f hello-vuln -l raptor_frida_linux_enum.js --pause
 *
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 */

// Enumerate all loaded modules
function enumAllModules()
{
	return Process.enumerateModules();
}

// Find all loaded modules that match a pattern
function findModules(pattern)
{
	var allModules = enumAllModules();
	var foundModules = [];

	allModules.forEach(function(aModule) {
		if (aModule.name.match(pattern)) {
			foundModules.push(aModule);
		}
	});

	return foundModules;
}

// Enumerate all functions using the `DebugSymbol` API
// NOTE: `Module.enumerateSymbols()` and `Module.findSymbolByName()` don't work
function enumAllFunctions()
{
	var allFunctions = [];

	for (const aFunction of DebugSymbol.findFunctionsMatching("*")) {
		allFunctions.push(DebugSymbol.fromAddress(ptr(aFunction)));
	}

	return allFunctions;
}

// Find all functions that match a glob using the `DebugSymbol` API
// NOTE: `Module.enumerateSymbols()` and `Module.findSymbolByName()` don't work
function findFunctions(glob)
{
	var matchingFunctions = []

	for (const aFunction of DebugSymbol.findFunctionsMatching(glob)) {
		matchingFunctions.push(DebugSymbol.fromAddress(ptr(aFunction)));
	}

	return matchingFunctions;
}

// Enumerate all functions in a module using the `DebugSymbol` API
// NOTE: `Module.enumerateSymbols()` and `Module.findSymbolByName()` don't work
function enumModuleFunctions(moduleName)
{
	var moduleFunctions = [];

	for (const aFunction of enumAllFunctions()) {
		if (aFunction.moduleName === moduleName) {
			moduleFunctions.push(aFunction)
		}
	}

	return moduleFunctions;
}

// Enumerate the imports of a module
function enumModuleImports(moduleName)
{
	for (const aModule of enumAllModules()) {
		if (aModule.name === moduleName) {
			return aModule.enumerateImports();
		}
	}
}

// Enumerate the exports of a module
function enumModuleExports(moduleName)
{
	for (const aModule of enumAllModules()) {
		if (aModule.name === moduleName) {
			return aModule.enumerateExports();
		}
	}
}

// Usage examples

// Enumerate all modules
/*
var l = enumAllModules()
l.forEach(function(m) { 
	//console.log(m.base, m.size, m.name, m.path); 
	console.log(m.base, m.name, m.path); 
});
*/

// Find modules that match a pattern
/*
var l = findModules(/lib/i);
l.forEach(function(m) { 
	//console.log(m.base, m.size, m.name, m.path); 
	console.log(m.base, m.name, m.path); 
});
*/

// Enumerate all functions
/*
var l = enumAllFunctions()
l.forEach(function(f) { 
	//console.log(f.address, f.name, f.moduleName, f.fileName, f.lineNumber);
	console.log(f.toString());
});
*/

// Find functions that match a glob
/*
var l = findFunctions("*printf*");
l.forEach(function(f) {
	//console.log(f.address, f.name, f.moduleName, f.fileName, f.lineNumber);
	console.log(f.toString())
});
*/

// Enumerate all functions in a module
/*
var l = enumModuleFunctions("hello-vuln")
l.forEach(function(f) { 
	console.log(f); 
});
*/

// Enumerate the imports of a module
/*
var l = enumModuleImports("hello-vuln");
l.forEach(function(i) {
	console.log(i.name);
});
*/

// Enumerate the exports of a module
/*
var l = enumModuleExports("libc.so.6");
l.forEach(function(e) {
	console.log(e.name);
});
*/
