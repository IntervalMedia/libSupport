#import "support_priv.h"
#import "hooks/hooks.h"
#import "fishhook/fishhook.h"
#import "litehook/litehook.h"
#import "memory/memory.h"

// Forward declaration for _NSGetEnviron() - Darwin system function
// Returns a pointer to the environment pointer, allowing safe environment manipulation
extern char ***_NSGetEnviron(void);

/*
 * Global flag to control environment hijacking method.
 * When true: Uses fishhook to intercept getenv() calls (lightweight approach)
 * When false: Uses _NSGetEnviron() to modify environment pointer directly (robust approach)
 * Default: false (uses _NSGetEnviron() method for maximum robustness)
 */
bool SupportUseFishhookEnvironmentHijacking = false;

// Original getenv function pointer for fishhook approach
static char* (*original_getenv)(const char* name) = NULL;

LS_STATIC NSString* _bundlePath;
LS_STATIC NSString* _bundleIdentifier = nil;
LS_STATIC NSString* _teamIdentifier = nil;
LS_STATIC NSArray*  _restrictedFiles = nil;
LS_STATIC NSArray*  _restrictedSchemes = nil;

LS_STATIC const char* _lsInitCallerPath = NULL;
LS_STATIC dispatch_once_t _lsInitCallerPathToken = 0;

void _supportinit_caller(const void *addr)
{
	dispatch_once(&_lsInitCallerPathToken, ^{
        _lsInitCallerPath = dyld_image_path_containing_address(addr);
    });
}
 
const char* _supportinit_callerpath(void) 
{ return _lsInitCallerPath; }

const char* SupportGetLibraryPath(void)
{
	LS_STATIC const char* libraryPath = NULL;
	LS_STATIC dispatch_once_t onceToken = 0;
	dispatch_once(&onceToken, ^{
		libraryPath = dyld_image_path_containing_address((void *)&SupportGetLibraryPath);
	});
	return libraryPath;
}

/*
 * Hooked getenv function for fishhook approach.
 * Filters out sensitive environment variables that could reveal jailbreak/injection state.
 */
LS_STATIC char* hooked_getenv(const char* name) 
{
    if (!name) {
        return original_getenv ? original_getenv(name) : NULL;
    }
    
    // Filter out variables that indicate simulator or injection
    if (strcmp(name, "SIMULATOR_DEVICE_NAME") == 0 ||
        strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) {
        LS_LOG("hooked_getenv() Filtering out request for: %s", name);
        return NULL;  // Return NULL as if the variable doesn't exist
    }
    
    // For all other variables, call the original getenv
    return original_getenv ? original_getenv(name) : NULL;
}

/*
 * Environment hijacking using fishhook to intercept getenv() calls.
 * This is a lightweight approach that hooks getenv() function calls
 * instead of modifying the actual environment pointer.
 */
LS_STATIC void hijackEnvironmentFishhook(void) 
{
    LS_LOG("hijackEnvironmentFishhook() Setting up fishhook for getenv()");
    
    // Set up the rebinding structure for fishhook
    struct rebinding getenv_rebinding = {
        .name = "getenv",
        .replacement = hooked_getenv,
        .replaced = (void**)&original_getenv
    };
    
    // Apply the hook
    int result = rebind_symbols(&getenv_rebinding, 1);
    if (result != 0) {
        LS_LOG("hijackEnvironmentFishhook() Failed to hook getenv(), error: %d", result);
        return;
    }
    
    LS_LOG("hijackEnvironmentFishhook() Successfully hooked getenv() function");
    
    // Test the hook by calling getenv on filtered variables
    char* test1 = getenv("SIMULATOR_DEVICE_NAME");
    char* test2 = getenv("DYLD_INSERT_LIBRARIES");
    LS_LOG("hijackEnvironmentFishhook() Test calls - SIMULATOR_DEVICE_NAME: %s, DYLD_INSERT_LIBRARIES: %s", 
           test1 ? test1 : "NULL", test2 ? test2 : "NULL");
}

/*
 * Environment hijacking using _NSGetEnviron() to modify environment pointer directly.
 * This is the robust approach that actually modifies the environment data structure.
 * Compatible with iOS 18.0+ and ARM64 architectures.
 */
LS_STATIC void hijackEnvironmentDirect(void) 
{
    LS_LOG("hijackEnvironmentDirect() Using _NSGetEnviron() approach");
    
    // Log the original environment for debugging
    LS_LOG("hijackEnvironmentDirect() Original environment before modification:");
    for(char* *env = environ; *env != 0; env++)
    {
        LS_LOG("hijackEnvironmentDirect() Env var: %s", *env);
    }

    /*
     * Use _NSGetEnviron() to get the canonical environment pointer.
     * This is the robust, Apple-sanctioned way to access the environment
     * pointer on Darwin systems (iOS, macOS). It works reliably on ARM64
     * and respects Apple's memory protection schemes.
     */
    char ***environPtr = _NSGetEnviron();
    if (!environPtr) 
    {
        LS_LOG("hijackEnvironmentDirect() Failed to get environment pointer via _NSGetEnviron()");
        return;
    }

    LS_LOG("hijackEnvironmentDirect() Successfully acquired environment pointer: %p", (void *)environPtr);

    // Count existing environment variables
    size_t count = 0;
    while (environ[count]) count++;

    /*
     * Allocate new environment array. Using NSMutableData ensures proper
     * memory management and alignment on ARM64. The data is retained in
     * static storage to prevent deallocation.
     */
    static NSMutableData *newEnvironData = nil;
    newEnvironData = [NSMutableData dataWithLength:(count + 1) * sizeof(char *)];
    char **newEnviron = (char **)newEnvironData.mutableBytes;
    size_t newIndex = 0;

    /*
     * Filter environment variables that could reveal jailbreak/modification state.
     * This preserves the core functionality while removing sensitive indicators.
     */
    for (size_t i = 0; i < count; i++) 
    {
        char *entry = environ[i];
        
        // Skip variables that indicate simulator or injection
        if (strstr(entry, "SIMULATOR_DEVICE_NAME") != NULL ||
            strstr(entry, "DYLD_INSERT_LIBRARIES") != NULL) 
        {
            LS_LOG("hijackEnvironmentDirect() Filtering out: %s", entry);
            continue;
        }
        
        // Copy all other environment variables
        newEnviron[newIndex++] = entry;
    }

    newEnviron[newIndex] = NULL;

    /*
     * Update the environment pointer directly. This is safe on ARM64 and
     * iOS 18.0+ because:
     * 1. _NSGetEnviron() provides the correct memory location
     * 2. The pointer update is atomic on ARM64
     * 3. No memory protection violations occur with this approach
     */
    *environPtr = newEnviron;

    LS_LOG("hijackEnvironmentDirect() Successfully updated environment pointer");

    // Verify the modifications took effect
    LS_LOG("hijackEnvironmentDirect() Modified environment after hijacking:");
    for (size_t i = 0; i < newIndex; i++) 
    {
        if (newEnviron[i] != NULL) 
        {
            LS_LOG("hijackEnvironmentDirect() New env var %zu: %s", i, newEnviron[i]);
        }
    }
}

/*
 * Robust Environment Hijacking for iOS 18.0+ and ARM64
 * 
 * This implementation provides two approaches for environment hijacking:
 * 1. Fishhook approach: Intercepts getenv() calls (lightweight, controlled by global flag)
 * 2. Direct approach: Uses _NSGetEnviron() to modify environment pointer (robust, default)
 * 
 * The method is controlled by the global SupportUseFishhookEnvironmentHijacking flag.
 * Both approaches filter out SIMULATOR_DEVICE_NAME and DYLD_INSERT_LIBRARIES to hide
 * jailbreak/injection indicators.
 */
LS_IGNORE LS_STATIC
void hijackEnvironment(void) 
{
    if (SupportUseFishhookEnvironmentHijacking) {
        LS_LOG("hijackEnvironment() Using fishhook approach for getenv() interception");
        hijackEnvironmentFishhook();
    } else {
        LS_LOG("hijackEnvironment() Using direct approach with _NSGetEnviron()");
        hijackEnvironmentDirect();
    }
}

// Early enter to register our stuff
// LS_CTOR_(0) { dyld_register_funcs(); }

LS_STATIC 
void _support_invalidate_restricted_loadcommands(void)
{
	mach_header_t *mh = (mach_header_t *)_dyld_get_image_header(0);
	if(!mh) return;

	const struct load_command* lc = (const struct load_command*)((uintptr_t)mh + sizeof(mach_header_t));
	for (uint32_t i = 0; i < mh->ncmds; i++) 
	{
		if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB) 
		{
			struct dylib_command* dylib_cmd = (struct dylib_command*)lc;
			char* dylib_name = (char*)dylib_cmd + dylib_cmd->dylib.name.offset;

			if(isCPathRestricted(dylib_name))
			{
				LS_LOG("SupportInvalidateRestrictedLoadCommands() detected restricted dylib: %s", dylib_name);
                
				// TODO: Implement proper dylib command invalidation
				// Currently disabled due to memory protection issues
				// Plan: modify dylib_cmd->cmd to LC_ID_DYLIB or patch dylib_name
				
				LS_LOG("_supportmem_code_patch: dylib invalidation not implemented yet");
			}
		}
		lc = (const struct load_command*)((uintptr_t)lc + lc->cmdsize);
	}
}

LS_STATIC 
BOOL _supportinitialize_config(SupportEntryInfo *info)
{
	if (LS_UNLIKELY(info == NULL))
	{
		LS_LOG("SupportInitialConfig() Invalid Argument: Expected non-NULL SupportEntryInfo, but received: " LS_TOSTRING(LSM_INVALID_ARGUMENTS));
		return NO;
	}

	_bundlePath = [getExecutablePath() stringByDeletingLastPathComponent];

	_bundlePath = getStandardizedPath(_bundlePath);

	if (info->bundleIdentifier != NULL)
	{
		_bundleIdentifier = [[NSString alloc] initWithCString:info->bundleIdentifier 
													 encoding:NSUTF8StringEncoding];
	}

	if (info->teamIdentifier != NULL)
	{
		_teamIdentifier = [[NSString alloc] initWithCString:info->teamIdentifier 
													 encoding:NSUTF8StringEncoding];
	}

    NSMutableArray *restrictedFiles = [NSMutableArray new];
	for (size_t i = 0; i < info->restrictedFileCount; i++)
	{
		[restrictedFiles addObject:[NSString stringWithUTF8String: info->restrictedFiles[i]]];
	}
	_restrictedFiles = [restrictedFiles copy];

	NSMutableArray *restrictedSchemes = [NSMutableArray arrayWithArray:@[@"cydia", @"undecimus", @"sileo", @"zbra", @"filza"]];
	for (size_t i = 0; i < info->restrictedURLSchemeCount; i++) {
		[restrictedSchemes addObject:[NSString stringWithUTF8String: info->restrictedURLSchemes[i]]];
	}
	_restrictedSchemes = [restrictedSchemes copy];

	return YES;
}

#pragma mark - libsupport export
 
void SupportInitialize(SupportEntryInfo* info)
{
	if(!_supportinitialize_config(info)) return;

	// TODO: maybe ugh
	// Allow the caller of SupportInitilize to bypass hook calls 
	// so that they don't receive sanitized data.
	_supportinit_caller(LS_CALLER_ADDRESS());

	LS_LOG("SupportGetLibraryPath(): %s", SupportGetLibraryPath());

	//this is wrong.
	//sandbox_hooks();
	//hijackEnvironment();

	SupportHookFlags hf = info->hookFlags;

	if(hf & SupportHookFlagDynamicLibraries)
	{
		LS_LOG("dyld");
		_supporthook_dyld();
	}

	if(hf & SupportHookFlagAntiProxyAndVPN)
	{
		LS_LOG("proxy");
		_supporthook_CFNetwork_antiproxy();
	}
	if(hf & SupportHookFlagFilesystem)
	{
		LS_LOG("filesystem");
		_supporthook_libc();
		_supporthook_NSFileManager();
	}
	if(hf & SupportHookFlagURLScheme)
	{
		LS_LOG("urlscheme");
		_supporthook_UIApplication();
	}
	if(hf & SupportHookFlagFoundation)
	{
		LS_LOG("foundation");
		_supporthook_NSBundle();
		_supporthook_NSData();
		_supporthook_NSString();
		_supporthook_NSURL();
		_supporthook_NSArray();
		_supporthook_NSDictionary();
		_supporthook_UIImage();
		_supporthook_NSProcessInfo_antiemulator();
	}
	if(hf & SupportHookFlagCoreFoundation)
	{
		LS_LOG("corefoundation");
		_supporthook_CFBundle();
	}
	if(hf & SupportHookFlagDeviceCheck)
	{
		LS_LOG("devicecheck");
		_supporthook_DeviceCheck();
	}
	if(hf & SupportHookFlagObjCRuntime)
	{
		LS_LOG("objc_runtime");
		_supporthook_objc_runtime();
	}
	
	if(hf & SupportHookFlagSecurity)
	{
		LS_LOG("security");
		_supporthook_SecTask();
	}
	if(hf & SupportHookFlagAntiDebugging)
	{
		LS_LOG("debug");
		_supporthook_libc_antidebug();
	}
	if(hf & SupportHookFlagSyscall)
	{
		LS_LOG("syscall");
		_supporthook_syscall();
	}
	if(hf & SupportHookFlagSymLookup)
	{
		LS_LOG("dlfcn");
		_supporthook_dyld_symlookup();
		_supporthook_dyld_symaddrlookup();
	}

	_support_invalidate_restricted_loadcommands();

	// spoof ourselves, confuse any malware detections?
    Dl_info self_info;
    dladdr((void *)SupportInitialize, &self_info);
	size_t page_size = getpagesize();
	uintptr_t base_addr = (uintptr_t)(self_info.dli_fbase);
	size_t prot_size = (size_t)((base_addr + page_size - 1) & ~(page_size - 1));
	_supportmem_protect((void*)base_addr, prot_size, (LSM_PROT_READ|LSM_PROT_EXEC));
}

void SupportHookSymbolEx(const char* symbol, void* replacement, void* *original) 
{
	# if 1
	struct rebinding rebindings[] = {  
		{
			.name = symbol,
			.replacement = replacement,
			.replaced = original
		}
	}; 

	rebind_symbols(rebindings, LS_ARRAYSIZE(rebindings));
	#else
	void *symaddr = dlsym(RTLD_DEFAULT, symbol);
	if(symaddr)
	{
		if(original)
		{
			*original = symaddr;
		}

		litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, symaddr, replacement, NULL);
	}
	#endif
}

int SupportMemoryProtectEx(void *addr, size_t size, int protection)
{
	return _supportmem_protect(addr, size, protection);
}
 
int SupportHookFunctionEx(SupportHookInfo hookInfo)
{
	void* address = hookInfo.address;
	void* replacement = hookInfo.replacement;
	void** original = hookInfo.original;

	// Add basic parameter validation
	if (address == NULL || replacement == NULL) {
		LS_LOG("SupportHookFunctionEx(): invalid parameters (address=%p, replacement=%p)", address, replacement);
		return LSM_INVALID_ARGUMENTS;
	}

	return _supportmem_hookfunction_64(address, replacement, original);
}
 
int SupportDestroy(SupportHookInfo hookInfo)
{ 
	// Check if we have a valid pointer to a pointer and if the dereferenced pointer is not NULL
	if(hookInfo.original != NULL && *hookInfo.original != NULL)
	{ 
		free(*hookInfo.original);
		*hookInfo.original = NULL; // Nullify the caller's pointer to prevent double-free
	} 
	return LSM_SUCCESS;
}
 
int SupportCodePatchEx(void* addr, const uint8_t* buffer, size_t size)
{
	// Add basic parameter validation
	if (addr == NULL || buffer == NULL || size == 0) {
		LS_LOG("SupportCodePatchEx(): invalid parameters (addr=%p, buffer=%p, size=%zu)", addr, buffer, size);
		return LSM_INVALID_ARGUMENTS;
	}
	return _supportmem_code_patch(addr, buffer, size);
}
 
void SupportRunOnMainQueueWithoutDeadlocking(void (*callback)(void*), void* data)
{
    if ([NSThread isMainThread]){ callback(data); } 
	else { dispatch_sync(dispatch_get_main_queue(), ^{ callback(data); }); }
}

# if 0 
void SupportGetApplicationWindowInfo(SupportApplicationWindowInfo *info) {
	id window = SupportGetKeyWindowInternal();
	id rootViewController = ((UIWindow *)window).rootViewController;
	id currentRootViewController = SupportGetCurrentViewControllerFrom(rootViewController);

	info->window = (__bridge const void *)window;
	info->rootViewController = (__bridge const void *)rootViewController;
	info->currentRootViewController = (__bridge const void *)currentRootViewController;
}
#endif
 
void SupportGetDetectionInfo(SupportDetectionInfo* detectionInfo) 
{
	if (LS_UNLIKELY(detectionInfo == NULL)) 
		return;
    
	if(LS_LIKELY(!detectionInfo->isJailbroken))
	{
		detectionInfo->isJailbroken = access("/var/mobile", R_OK) == 0;
	}

	if(LS_LIKELY(!detectionInfo->isDebuggerPresent))
	{
		int flags = 0;
    	csops(getpid(), 0, &flags, sizeof(flags));
    	detectionInfo->isDebuggerPresent = (flags & CS_DEBUGGED) != 0;
	}
}

const char* SupportGetVersion()
{
	return LIBRARY_BUILD_VERSION;
}


#pragma mark - libsupport private api impl

BOOL isAddrRestricted( const void * addr ) {
    if(addr) {
        // See if this address belongs to a restricted file.
        const char* image_path = dyld_image_path_containing_address(addr);
        return isCPathRestricted(image_path);
    }

    return NO;
}

BOOL isCFURLRestricted( CFURLRef path )
{
    NSURL* result = (__bridge NSURL *)(path);
    return isURLRestricted(result);
}

BOOL isCFPathRestricted( CFStringRef path )
{
    NSString* result = (__bridge NSString *)(path);
    return isPathRestricted(result);
}

BOOL isURLRestricted( NSURL* url )
{
    if(!url) return NO;
    if([url isFileURL]) 
    {
        NSString* path = [url path];

        if([url isFileReferenceURL]) 
        {
            NSURL *surl = [url standardizedURL];

            if(surl) 
            {
                path = [surl path];
            }            
        }

        if(isPathRestricted(path))
        {
            return YES;
        }
    }

	return isSchemeRestricted([url scheme]);
}

BOOL isPathRestricted( NSString* path )
{
    if (!path || ![path respondsToSelector:@selector(rangeOfString:)]) return NO;
    for (NSString* file in getRestrictedFiles())
    {
        if ([file characterAtIndex:0] == '/' && [path respondsToSelector:@selector(hasPrefix:)] && [path hasPrefix:file]) return YES;
        if ([path rangeOfString:file].location != NSNotFound) return YES;
    }

    return NO;
}

BOOL isCPathRestricted(const char* path)
{
	if(path)
	{
        return isPathRestricted([[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)]);
	}
	return NO;
}

LS_FORCE_INLINE NSString* getBundlePath() { return _bundlePath; }
LS_FORCE_INLINE NSString* getBundleIdentifier(){ return _bundleIdentifier; }
LS_FORCE_INLINE NSString* getTeamIdentifier(){ return _teamIdentifier; }
LS_FORCE_INLINE NSArray* getRestrictedFiles(){ return _restrictedFiles; }

BOOL isAddrExternal(const void *addr) 
{
	if(!addr) return NO;

    const char* image_path = dyld_image_path_containing_address(addr);
	if(!image_path) return NO;

	if(strcmp(image_path, SupportGetLibraryPath()) == 0)
	{
		return NO;
	}

	// FIXME:
	//if(strcmp(image_path, SupportInitCallerPath()) == 0)
	//{
	//	return NO;
	//}

	return YES;
}

# if 0
// Shadow impl (ref)
BOOL isAddrExternal(const void *addr) 
{
	if(!addr) return NO;

    const char* image_path = dyld_image_path_containing_address(addr);
	if(!image_path) return NO;

    if (strstr(image_path, [getBundlePath() fileSystemRepresentation]) != NULL) 
    {
		if (strstr(image_path, "libSupport.dylib") != NULL) 
        {
            return YES; // Treat libSupport as external even though it's within the app's bundle.
        }
        return NO; // It's internal
    }

    return YES; // It's external
}
#endif

#pragma mark - libsupport utilities

id getAdjustedDictionary(NSBundle *bundle, id dictionary, BOOL mutable)
{
    NSMutableDictionary *mutableDictionary = mutable ? dictionary : [dictionary mutableCopy];
	
    if (bundle == NSBundle.mainBundle)
    {
		NSString *adjustedBundleIdentifier = getBundleIdentifier();
		if (adjustedBundleIdentifier != nil)
		{
			static NSString *bundleIdentifierKey = @"CFBundleIdentifier";
			if ([mutableDictionary objectForKey:bundleIdentifierKey] != nil)
			{
				[mutableDictionary setObject:adjustedBundleIdentifier forKey:bundleIdentifierKey];
			}

			// Fix for iosgods spoofer thing remove this shit wtf dude, by default sideloadly adds this to the info.plist file
			// libSupport is not compatible with their spoofer, it will just crash the app
			// We are trying to restore the info.plist to its original state and these guys are adding on to it lol
			static NSString *altBundleIdentifierKey = @"ALTBundleIdentifier";
        	if ([mutableDictionary objectForKey:altBundleIdentifierKey] != nil)
			{
            	[mutableDictionary removeObjectForKey:altBundleIdentifierKey];
			}
		}
    }

	// return the original sate
    return mutable ? mutableDictionary : [mutableDictionary copy];
}

NSString *getStandardizedPath(NSString *path)
{
    if(!path) {
        return path;
    }

    NSURL* url = [NSURL URLWithString:path];

    if(!url) {
        url = [NSURL fileURLWithPath:path];
    }

    NSString* standardized_path = [[url standardizedURL] path];

    if(standardized_path) {
        path = standardized_path;
    }

    while([path containsString:@"/./"]) {
        path = [path stringByReplacingOccurrencesOfString:@"/./" withString:@"/"];
    }

    while([path containsString:@"//"]) {
        path = [path stringByReplacingOccurrencesOfString:@"//" withString:@"/"];
    }

    if([path length] > 1) {
        if([path hasSuffix:@"/"]) {
            path = [path substringToIndex:[path length] - 1];
        }

        while([path hasSuffix:@"/."]) {
            path = [path stringByDeletingLastPathComponent];
        }
        
        while([path hasSuffix:@"/.."]) {
            path = [path stringByDeletingLastPathComponent];
            path = [path stringByDeletingLastPathComponent];
        }
    }

    if([path hasPrefix:@"/private/var"] || [path hasPrefix:@"/private/etc"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    if([path hasPrefix:@"/var/tmp"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    return path;
}

// taken from oppa (TrollStore)
// ref: https://github.com/opa334/TrollStore/blob/704d3ffd45f90edc2ba796511222079b5d69cfd4/Shared/TSUtil.m#L29
extern char*** _NSGetArgv();
NSString* getExecutablePath()
{
	//char* executablePathC = **_NSGetArgv();
	//return [NSString stringWithUTF8String:executablePathC];

	return [[NSProcessInfo processInfo].arguments firstObject];
}

LS_FORCE_INLINE
BOOL isSchemeRestricted(NSString * scheme) 
{
    return [_restrictedSchemes containsObject:scheme];
}
