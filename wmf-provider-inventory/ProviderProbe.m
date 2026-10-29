#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <sys/utsname.h>

static NSDictionary *imageInfo(const struct mach_header *header, const char *path) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"path"] = path ? [NSString stringWithUTF8String:path] : @"";
    result[@"magic"] = @(header->magic);
    result[@"cpu_type"] = @(header->cputype);
    result[@"cpu_subtype"] = @(header->cpusubtype);
    result[@"ncmds"] = @(header->ncmds);
    result[@"sizeofcmds"] = @(header->sizeofcmds);
    if (header->magic != MH_MAGIC_64) {
        result[@"supported_header"] = @NO;
        return result;
    }
    result[@"supported_header"] = @YES;
    const unsigned char *cursor = (const unsigned char *)header + sizeof(struct mach_header_64);
    const unsigned char *end = cursor + header->sizeofcmds;
    NSMutableArray *versions = [NSMutableArray array];
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) {
            result[@"malformed_commands"] = @YES;
            break;
        }
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) || command->cmdsize > (size_t)(end - cursor)) {
            result[@"malformed_commands"] = @YES;
            break;
        }
        if (command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uuid = (const struct uuid_command *)command;
            result[@"uuid"] = [[[NSUUID alloc] initWithUUIDBytes:uuid->uuid] UUIDString];
        }
        if (command->cmd == LC_BUILD_VERSION && command->cmdsize >= sizeof(struct build_version_command)) {
            const struct build_version_command *version = (const struct build_version_command *)command;
            [versions addObject:@{@"platform": @(version->platform), @"minos_bits": @(version->minos),
                                 @"sdk_bits": @(version->sdk), @"ntools": @(version->ntools)}];
        }
        cursor += command->cmdsize;
    }
    result[@"build_versions"] = versions;
    return result;
}

int main(void) {
    @autoreleasepool {
        NSMutableDictionary *result = [NSMutableDictionary dictionary];
        result[@"scope"] = @"independently_authored_provider_identity_only";
        result[@"original_application_loaded_or_executed"] = @NO;
        result[@"provider_lifetime_or_source_effects_qualified"] = @NO;
        result[@"os_version"] = [[NSProcessInfo processInfo] operatingSystemVersionString];
        struct utsname host;
        if (uname(&host) == 0) {
            result[@"machine"] = [NSString stringWithUTF8String:host.machine];
            result[@"kernel_release"] = [NSString stringWithUTF8String:host.release];
        }
        dlerror();
        void *swift = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW | RTLD_LOCAL);
        result[@"swift_core_dlopen_succeeded"] = @(swift != NULL);
        const char *error = dlerror();
        if (error) result[@"swift_core_dlopen_error"] = [NSString stringWithUTF8String:error];
        NSMutableArray *images = [NSMutableArray array];
        for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
            const char *path = _dyld_get_image_name(i);
            NSString *name = path ? [NSString stringWithUTF8String:path] : @"";
            if ([name containsString:@"Foundation"] || [name containsString:@"libswiftCore"] ||
                [name containsString:@"libobjc"] || [name containsString:@"libdispatch"] ||
                [name containsString:@"libsystem_blocks"] || i == 0)
                [images addObject:imageInfo(_dyld_get_image_header(i), path)];
        }
        result[@"loaded_images"] = images;
        NSMutableArray *symbols = [NSMutableArray array];
        const char *names[] = {"dispatch_source_set_event_handler", "_Block_copy", "_Block_release",
                               "objc_retain", "objc_release", "swift_retain", "swift_release"};
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
            void *address = dlsym(RTLD_DEFAULT, names[i]);
            if (!address && swift) address = dlsym(swift, names[i]);
            NSMutableDictionary *symbol = [@{@"name": [NSString stringWithUTF8String:names[i]],
                                             @"resolved": @(address != NULL)} mutableCopy];
            Dl_info info;
            if (address && dladdr(address, &info) && info.dli_fbase)
                symbol[@"provider"] = imageInfo((const struct mach_header *)info.dli_fbase, info.dli_fname);
            [symbols addObject:symbol];
        }
        result[@"resolved_symbols"] = symbols;
        NSError *jsonError = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:&jsonError];
        if (!json) {
            fprintf(stderr, "%s\n", [[jsonError description] UTF8String]);
            return 1;
        }
        fwrite([json bytes], 1, [json length], stdout);
        fputc('\n', stdout);
        return swift ? 0 : 2;
    }
}
