# a collection of frida scripts
# source:
# https://github.com/poxyran/misc
# and so on.

def show_modules(session):
    """show module names"""

    def on_message(message, data):
        print("[%s] -> %s" % (message, data))

    script = session.create_script("""
        Process.enumerateModules({
            onMatch: function(module){
                console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
            }, 
            onComplete: function(){}
        });
    """)

    script.on('message', on_message)
    script.load()
    return script


def show_modules_sync(session):
    """
    (sync) show module names

    Usage:
    script = show_modules_sync(session)
    res = script.exports.show_modules_sync()
    for x in res:
        print(x)
    """

    def on_message(message, data):
        print("[%s] -> %s" % (message, data))

    script = session.create_script("""
        function show_modules(){
            return Process.enumerateModulesSync();
        }
        rpc.exports = {
            showModulesSync: function(){
                return show_modules();
            }
        }
    """)

    script.on('message', on_message)
    script.load()
    return script


def show_imports(session, module_name):
    """show module imports (no output?)"""

    def on_message(message, data):
        print("[%s] -> %s" % (message, data))

    script = session.create_script("""
        Module.enumerateImports('""" + module_name + """', {
                onMatch: function(imp){
                    console.log('Module type: ' + imp.type + ' - Name: ' + imp.name + ' - Module: ' + imp.module + ' - Address: ' + imp.address.toString());
                }, 
                onComplete: function(){}
            });
    """)

    script.on('message', on_message)
    script.load()
    return script


def process_stalker(session):
    """show which function is called/which event is triggered(?)"""

    def on_message(message, data):
        print("[%s] -> %s" % (message, data))

    script = session.create_script("""
        function StalkerExeample() 
        {
            var threadIds = [];
            Process.enumerateThreads({
                onMatch: function (thread) 
                {
                    threadIds.push(thread.id);
                    console.log("Thread ID: " + thread.id.toString());
                },
                onComplete: function () 
                {
                    threadIds.forEach(function (threadId) 
                        {
                            Stalker.follow(threadId, 
                            {
                                events: {call: true},

                            onReceive: function (events)
                            {
                                console.log("onReceive called.");
                            },
                            onCallSummary: function (summary)
                            {
                                console.log("onCallSummary called.");
                            }
                        });
                    });
                }
            });
        }
        StalkerExeample();
    """)

    script.on('message', on_message)
    script.load()
    return script


def get_module_address_quick(session, module_name):
    """
    get module address by module name with built-in findBaseAddress

    Usage:
    script = get_module_address(session, 'hello')
    base_addr = script.exports.get_module_address()
    """

    def on_message(message, data):
        print("[%s] -> %s" % (message, data))

    script = session.create_script("""
        const moduleName = '""" + module_name + """';
        function module_address(){
            return Module.findBaseAddress(moduleName)
        }
        rpc.exports = {
            getModuleAddress: function() {
                return module_address();
            }
        }
    """)

    script.on('message', on_message)
    script.load()
    return script


def get_module_address(session, module_name):
    """
    get module address by module name (slow)

    Usage:
    script = get_module_address(session, 'hello')
    base_addr = script.exports.get_module_address()
    """

    def on_message(message, data):
        print("[%s] -> %s" % (message, data))

    script = session.create_script("""
        function module_address(){
            var result = "";
            Process.enumerateModules({
                onMatch: function(module){
                    if ('""" + module_name + """' == module.name) {
                        console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
                        result = module.base;
                    }
                }, 
                onComplete: function(){}
            });
            return result;
        }
        rpc.exports = {
            getModuleAddress: function() {
                return module_address();
            }
        }
    """)

    script.on('message', on_message)
    script.load()
    return script


def get_module_function_address(session):
    """
    get function address (Linux only?)

    working methods
    DebugSymbol.getFunctionByName
    DebugSymbol.fromName

    P.S. `Module.findExportByName("hello.exe", function_name)` does not work

    :param session:
    :return:

    usage:
    script = get_module_function_address(session)
    function_address = script.exports.get_module_function_address('f')
    """

    def on_message(message, data):
        print("[%s] -> %s" % (message, data))

    script = session.create_script("""
        function get_func_address(function_name) {
            // works
            return DebugSymbol.getFunctionByName(function_name);
            // works
            // return DebugSymbol.fromName(function_name).address;
        }

        rpc.exports = {
            getModuleFunctionAddress: function (function_name){
                return get_func_address(function_name);
            }
        }
    """)

    script.on('message', on_message)
    script.load()
    return script
