import frida
import sys
import time
import psutil
import threading
from pathlib import Path

FORBIDDEN_APIS = [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", 
    "OutputDebugStringA",
    "OutputDebugStringW",
    "NtQueryInformationProcess",
    "ZwQueryInformationProcess",
    "DebugActiveProcess",
    "DebugBreak",
    "DebugSetProcessKillOnExit",
    "ContinueDebugEvent",
    "NtSetInformationThread",
    "NtQuerySystemInformation",
    "GetTickCount",
    "QueryPerformanceCounter",
    "timeGetTime"
]

# Comprehensive module mapping
API_MODULES = {
    "IsDebuggerPresent": ["kernel32.dll", "kernelbase.dll", "api-ms-win-core-debug-l1-1-0.dll"],
    "CheckRemoteDebuggerPresent": ["kernel32.dll", "kernelbase.dll", "api-ms-win-core-debug-l1-1-0.dll"],
    "OutputDebugStringA": ["kernel32.dll", "kernelbase.dll"],
    "OutputDebugStringW": ["kernel32.dll", "kernelbase.dll"],
    "NtQueryInformationProcess": ["ntdll.dll"],
    "ZwQueryInformationProcess": ["ntdll.dll"],
    "DebugActiveProcess": ["kernel32.dll", "kernelbase.dll"],
    "DebugBreak": ["kernel32.dll", "kernelbase.dll"],
    "DebugSetProcessKillOnExit": ["kernel32.dll", "kernelbase.dll"],
    "ContinueDebugEvent": ["kernel32.dll", "kernelbase.dll"],
    "NtSetInformationThread": ["ntdll.dll"],
    "NtQuerySystemInformation": ["ntdll.dll"],
    "GetTickCount": ["kernel32.dll", "kernelbase.dll"],
    "QueryPerformanceCounter": ["kernel32.dll", "kernelbase.dll"],
    "timeGetTime": ["winmm.dll"]
}

JS_SCRIPT = """
var violationDetected = false;
var hookedFunctions = new Set();
var detectedCalls = [];
const forbidden = %s;
const apiModules = %s;

console.log("[INIT] Starting comprehensive anti-debugging detection...");

// Enhanced module enumeration
function enumerateAllModules() {
    const modules = Process.enumerateModules();
    console.log("[MODULES] Found " + modules.length + " loaded modules:");
    modules.forEach(function(module) {
        console.log("[MODULE] " + module.name + " @ " + module.base);
    });
    return modules;
}

// More aggressive hooking with multiple attempts
function attemptHook(functionName, moduleName) {
    try {
        const addr = Module.getExportByName(moduleName, functionName);
        if (addr && !hookedFunctions.has(functionName + "@" + moduleName)) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    const caller = Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).slice(0, 3);
                    
                    console.log("[FORBIDDEN] *** ANTI-DEBUG DETECTED ***");
                    console.log("[FORBIDDEN] Function: " + functionName);
                    console.log("[FORBIDDEN] Module: " + moduleName);
                    console.log("[FORBIDDEN] Address: " + addr);
                    console.log("[FORBIDDEN] Caller: " + caller[0]);
                    
                    violationDetected = true;
                    detectedCalls.push({
                        function: functionName,
                        module: moduleName,
                        address: addr.toString(),
                        timestamp: Date.now(),
                        caller: caller[0].toString()
                    });
                },
                onLeave: function(retval) {
                    if (functionName === "IsDebuggerPresent") {
                        console.log("[FORBIDDEN] IsDebuggerPresent returned: " + retval);
                        // Optionally modify return value to bypass detection
                        // retval.replace(0);
                    }
                }
            });
            hookedFunctions.add(functionName + "@" + moduleName);
            console.log("[HOOK] ✓ Successfully hooked: " + functionName + " in " + moduleName);
            return true;
        }
    } catch (err) {
        // Silent failure for unavailable functions
        return false;
    }
    return false;
}

// Comprehensive hooking strategy
function hookAllAvailableApis() {
    let hooksAdded = 0;
    
    // First, enumerate all available modules
    const availableModules = Process.enumerateModules().map(m => m.name.toLowerCase());
    console.log("[HOOK] Available modules: " + availableModules.join(", "));
    
    for (const functionName of forbidden) {
        // Try specific modules first
        if (apiModules[functionName]) {
            for (const moduleName of apiModules[functionName]) {
                if (availableModules.includes(moduleName.toLowerCase())) {
                    if (attemptHook(functionName, moduleName)) {
                        hooksAdded++;
                        break; // Move to next function once hooked
                    }
                }
            }
        }
        
        // If not hooked yet, try global search
        if (!Array.from(hookedFunctions).some(h => h.startsWith(functionName + "@"))) {
            try {
                const addr = Module.getExportByName(null, functionName);
                if (addr) {
                    // Find which module this address belongs to
                    const modules = Process.enumerateModules();
                    for (const module of modules) {
                        if (addr.compare(module.base) >= 0 && 
                            addr.compare(module.base.add(module.size)) < 0) {
                            if (attemptHook(functionName, module.name)) {
                                hooksAdded++;
                                break;
                            }
                        }
                    }
                }
            } catch (err) {
                console.log("[INFO] Function not available globally: " + functionName);
            }
        }
    }
    
    return hooksAdded;
}

// Hook process creation and module loading
function hookProcessEvents() {
    // Hook LdrLoadDll for comprehensive module loading detection
    try {
        const ldrLoadDll = Module.getExportByName("ntdll.dll", "LdrLoadDll");
        if (ldrLoadDll) {
            Interceptor.attach(ldrLoadDll, {
                onEnter: function(args) {
                    this.moduleName = null;
                    try {
                        if (!args[2].isNull()) {
                            this.moduleName = Memory.readUtf16String(args[2].readPointer());
                        }
                    } catch (e) {}
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.moduleName) {
                        console.log("[MODULE] New module loaded via LdrLoadDll: " + this.moduleName);
                        setTimeout(function() {
                            const newHooks = hookAllAvailableApis();
                            if (newHooks > 0) {
                                console.log("[HOOK] Added " + newHooks + " hooks after LdrLoadDll");
                            }
                        }, 100);
                    }
                }
            });
            console.log("[HOOK] ✓ Hooked LdrLoadDll for module loading detection");
        }
    } catch (err) {
        console.log("[INFO] Could not hook LdrLoadDll: " + err.message);
    }
    
    // Hook GetProcAddress more comprehensively
    const getProcModules = ["kernel32.dll", "kernelbase.dll"];
    for (const moduleName of getProcModules) {
        try {
            const getProcAddr = Module.getExportByName(moduleName, "GetProcAddress");
            if (getProcAddr) {
                Interceptor.attach(getProcAddr, {
                    onEnter: function(args) {
                        try {
                            this.functionName = Memory.readAnsiString(args[1]);
                            if (forbidden.indexOf(this.functionName) !== -1) {
                                console.log("[FORBIDDEN] *** DYNAMIC RESOLUTION DETECTED ***");
                                console.log("[FORBIDDEN] GetProcAddress called for: " + this.functionName);
                                violationDetected = true;
                                detectedCalls.push({
                                    function: this.functionName,
                                    module: "GetProcAddress",
                                    address: "dynamic",
                                    timestamp: Date.now(),
                                    caller: "GetProcAddress"
                                });
                            }
                        } catch (err) {}
                    }
                });
                console.log("[HOOK] ✓ Hooked GetProcAddress in " + moduleName);
            }
        } catch (err) {
            continue;
        }
    }
}

// Hook main entry point to catch early calls
function hookEntryPoint() {
    try {
        const mainModule = Process.enumerateModules()[0];
        console.log("[ENTRY] Main module: " + mainModule.name + " @ " + mainModule.base);
        
        // Try to hook common entry points
        const entryPoints = ["main", "wmain", "WinMain", "wWinMain", "_main", "_wmain"];
        
        for (const entryName of entryPoints) {
            try {
                const entryAddr = Module.getExportByName(mainModule.name, entryName);
                if (entryAddr) {
                    Interceptor.attach(entryAddr, {
                        onEnter: function(args) {
                            console.log("[ENTRY] Entry point " + entryName + " called");
                            // Re-attempt hooking at entry point
                            setTimeout(function() {
                                const newHooks = hookAllAvailableApis();
                                console.log("[ENTRY] Re-hooked " + newHooks + " functions at entry point");
                            }, 10);
                        }
                    });
                    console.log("[HOOK] ✓ Hooked entry point: " + entryName);
                    break;
                }
            } catch (err) {
                continue;
            }
        }
    } catch (err) {
        console.log("[INFO] Could not hook entry points: " + err.message);
    }
}

// Initialize everything
console.log("[INIT] Setting up hooks...");
enumerateAllModules();
hookProcessEvents();
hookEntryPoint();

// Initial hooking attempt
const initialHooks = hookAllAvailableApis();
console.log("[INIT] Initial hooks established: " + initialHooks + "/" + forbidden.length);

// Periodic re-hooking to catch late-loaded modules
var rehookCount = 0;
var rehookInterval = setInterval(function() {
    rehookCount++;
    const newHooks = hookAllAvailableApis();
    if (newHooks > 0) {
        console.log("[PERIODIC] Cycle " + rehookCount + ": Added " + newHooks + " new hooks");
    }
    
    // Stop after 30 seconds
    if (rehookCount >= 30) {
        clearInterval(rehookInterval);
        console.log("[CLEANUP] Stopped periodic re-hooking");
    }
}, 1000);

console.log("[INIT] Anti-debugging detection fully initialized");
console.log("[STATUS] Monitoring " + hookedFunctions.size + " function hooks");

// Export functions for Python communication
rpc.exports = {
    check: function() {
        return !violationDetected;
    },
    getStatus: function() {
        return {
            violationDetected: violationDetected,
            hookedFunctions: Array.from(hookedFunctions),
            totalFunctions: forbidden.length,
            detectedCalls: detectedCalls
        };
    },
    getHookedCount: function() {
        return hookedFunctions.size;
    },
    getDetectedCalls: function() {
        return detectedCalls;
    },
    reset: function() {
        violationDetected = false;
        detectedCalls = [];
        return true;
    },
    forceHook: function() {
        return hookAllAvailableApis();
    }
};
""" % (str(FORBIDDEN_APIS), str(API_MODULES).replace("'", '"'))

def find_executable(name):
    """Find executable in current directory or PATH"""
    # Check current directory first
    current_dir = Path.cwd()
    exe_path = current_dir / name
    if exe_path.exists():
        return str(exe_path)
    
    # Check with .exe extension
    exe_path = current_dir / f"{name}.exe"
    if exe_path.exists():
        return str(exe_path)
    
    # If not found, return the name and let frida handle it
    return name

def run_test(executable_name="tictactoe.exe", args=None):
    """
    Run the anti-debugging detection test
    
    Args:
        executable_name: Name of the executable to test
        args: Additional arguments to pass to the executable
    """
    if args is None:
        args = ["activate"]
    
    pid = None
    session = None
    
    try:
        exe_path = find_executable(executable_name)
        command = [exe_path] + args
        
        print(f"[PYTHON] Spawning target process: {' '.join(command)}")
        
        # Use spawn to get full control over the process
        pid = frida.spawn(command, stdio='pipe')
        print(f"[PYTHON] Process spawned with PID: {pid}")
        
        # Attach immediately
        session = frida.attach(pid)
        print("[PYTHON] Attached to process")
        
        # Create and load script
        script = session.create_script(JS_SCRIPT)
        
        # Enhanced message handler
        def on_message(message, data):
            if message['type'] == 'send':
                print(f"[JS] {message['payload']}")
            elif message['type'] == 'error':
                print(f"[JS ERROR] {message['description']}")
                if 'stack' in message:
                    print(f"[JS STACK] {message['stack']}")
        
        script.on('message', on_message)
        
        print("[PYTHON] Loading Frida script...")
        script.load()
        
        # Wait for script initialization
        print("[PYTHON] Waiting for script initialization...")
        time.sleep(2.0)
        
        # Resume the process
        print("[PYTHON] Resuming target process...")
        frida.resume(pid)
        
        # Extended monitoring period with more frequent checks
        print("[PYTHON] Starting extended monitoring...")
        monitoring_duration = 30  # Monitor for 30 seconds
        check_interval = 0.5  # Check every 500ms
        
        for i in range(int(monitoring_duration / check_interval)):
            time.sleep(check_interval)
            
            try:
                # Get comprehensive status
                status = script.exports_sync.get_status()
                hooked_count = script.exports_sync.get_hooked_count()
                
                if i % 4 == 0:  # Print status every 2 seconds
                    print(f"[CHECK {i//4 + 1}] Hooked: {hooked_count}/{len(FORBIDDEN_APIS)}, "
                          f"Violation: {status['violationDetected']}")
                
                # Check for violations
                if status['violationDetected']:
                    print("\n" + "="*60)
                    print("[RESULT] *** ANTI-DEBUGGING FUNCTION DETECTED! ***")
                    print("="*60)
                    
                    detected_calls = script.exports_sync.get_detected_calls()
                    for call in detected_calls:
                        print(f"[DETECTION] Function: {call['function']}")
                        print(f"[DETECTION] Module: {call['module']}")
                        print(f"[DETECTION] Address: {call['address']}")
                        print(f"[DETECTION] Caller: {call['caller']}")
                        print(f"[DETECTION] Time: {call['timestamp']}")
                        print("-" * 40)
                    
                    return False
                    
            except Exception as e:
                print(f"[RPC ERROR] {e}")
                # Try to force re-hook on RPC errors
                try:
                    new_hooks = script.exports_sync.force_hook()
                    if new_hooks > 0:
                        print(f"[RECOVERY] Added {new_hooks} hooks after RPC error")
                except:
                    pass
        
        print("\n[RESULT] No anti-debugging functions detected during monitoring period")
        
        # Final status check
        try:
            final_status = script.exports_sync.get_status()
            print(f"[FINAL] Total hooks established: {len(final_status['hookedFunctions'])}")
            print(f"[FINAL] Functions monitored: {final_status['totalFunctions']}")
            
            if final_status['hookedFunctions']:
                print("[FINAL] Successfully hooked functions:")
                for func in final_status['hookedFunctions']:
                    print(f"  - {func}")
            else:
                print("[WARNING] No functions were successfully hooked!")
                print("[WARNING] This may indicate a problem with the detection script.")
        except Exception as e:
            print(f"[FINAL ERROR] {e}")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Comprehensive cleanup
        print("[PYTHON] Cleaning up...")
        
        if session:
            try:
                session.detach()
                print("[PYTHON] Session detached")
            except Exception as e:
                print(f"[CLEANUP] Session detach error: {e}")
        
        if pid:
            try:
                # Try graceful termination first
                process = psutil.Process(pid)
                process.terminate()
                
                # Wait for termination
                try:
                    process.wait(timeout=5)
                    print(f"[PYTHON] Process {pid} terminated gracefully")
                except psutil.TimeoutExpired:
                    # Force kill if graceful termination fails
                    process.kill()
                    process.wait(timeout=2)
                    print(f"[PYTHON] Process {pid} force killed")
                    
            except psutil.NoSuchProcess:
                print(f"[PYTHON] Process {pid} already terminated")
            except Exception as e:
                print(f"[CLEANUP] Process cleanup error: {e}")

def main():
    """Main function with command line argument support"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Anti-debugging detection tool using Frida')
    parser.add_argument('executable', nargs='?', default='tictactoe.exe',
                       help='Executable to test (default: tictactoe.exe)')
    parser.add_argument('--args', nargs='*', default=['activate'],
                       help='Arguments to pass to the executable (default: activate)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Monitoring timeout in seconds (default: 30)')
    
    args = parser.parse_args()
    
    print("="*60)
    print("COMPREHENSIVE ANTI-DEBUGGING DETECTION TOOL")
    print("="*60)
    print(f"Target: {args.executable}")
    print(f"Arguments: {' '.join(args.args)}")
    print(f"Monitoring APIs: {', '.join(FORBIDDEN_APIS[:5])}... ({len(FORBIDDEN_APIS)} total)")
    print("="*60)
    
    success = run_test(args.executable, args.args)
    
    if not success:
        print("\n❌ DETECTION FAILED - Anti-debugging functions were detected!")
        print("The target executable uses anti-debugging techniques.")
        sys.exit(1)
    else:
        print("\n✅ DETECTION PASSED - No anti-debugging functions detected.")
        print("The target executable appears clean.")
        sys.exit(0)

if __name__ == "__main__":
    main()