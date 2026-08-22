// SPDX-License-Identifier: GPL-3.0-only

#import "PrivateWiFiShim.h"

#import <CoreWLAN/CoreWLAN.h>
#import <dlfcn.h>
#import <objc/runtime.h>

NSErrorDomain const BPPrivateWiFiErrorDomain = @"local.bssid-picker.private-wifi";

typedef id _Nullable (*BPObjectGetter)(id, SEL);
typedef NSInteger (*BPIntegerGetter)(id, SEL);
typedef NSUInteger (*BPUIntegerGetter)(id, SEL);
typedef BOOL (*BPBoolGetter)(id, SEL);
typedef void (*BPObjectSetter)(id, SEL, id _Nullable);
typedef void (*BPBoolSetter)(id, SEL, BOOL);
typedef BOOL (*BPAssociateFunction)(id, SEL, id, NSError *__autoreleasing _Nullable *);

typedef NS_ENUM(NSInteger, BPNetworkAuthenticationKind) {
    BPNetworkAuthenticationPasswordless,
    BPNetworkAuthenticationPersonalPSK,
    BPNetworkAuthenticationWEP,
    BPNetworkAuthenticationEnterprise,
    BPNetworkAuthenticationUnknown,
};

static NSString *const BPPrivateFrameworkPath =
    @"/System/Library/PrivateFrameworks/CoreWiFi.framework/CoreWiFi";

static NSError *BPError(BPPrivateWiFiErrorCode code, NSString *description) {
    return [NSError errorWithDomain:BPPrivateWiFiErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey : description}];
}

static NSError *BPErrorWithUnderlying(BPPrivateWiFiErrorCode code,
                                      NSString *description,
                                      NSError *_Nullable underlyingError) {
    NSMutableDictionary<NSErrorUserInfoKey, id> *userInfo =
        [@{NSLocalizedDescriptionKey : description} mutableCopy];
    if (underlyingError != nil) {
        userInfo[NSUnderlyingErrorKey] = underlyingError;
    }
    return [NSError errorWithDomain:BPPrivateWiFiErrorDomain code:code userInfo:userInfo];
}

static void BPAssignError(NSError *__autoreleasing _Nullable *_Nullable target,
                          NSError *value) {
    if (target != NULL) {
        *target = value;
    }
}

static BOOL BPErrorHasCode(NSError *_Nullable error,
                           BPPrivateWiFiErrorCode code) {
    return error != nil &&
        [error.domain isEqualToString:BPPrivateWiFiErrorDomain] &&
        error.code == code;
}

BOOL BPIsCredentialDelegationUnavailableError(NSError *_Nullable error) {
    return BPErrorHasCode(error, BPPrivateWiFiErrorCredentialDelegationUnavailable);
}

BOOL BPIsUnsupportedAuthenticationError(NSError *_Nullable error) {
    return BPErrorHasCode(error, BPPrivateWiFiErrorUnsupportedAuthentication);
}

BOOL BPIsSSIDInvariantViolationError(NSError *_Nullable error) {
    return BPErrorHasCode(error, BPPrivateWiFiErrorSSIDInvariantViolation);
}

static const char *BPSkipTypeQualifiers(const char *type) {
    if (type == NULL) {
        return NULL;
    }
    while (*type == 'r' || *type == 'n' || *type == 'N' || *type == 'o' ||
           *type == 'O' || *type == 'R' || *type == 'V') {
        type++;
    }
    return type;
}

static BOOL BPTypesMatch(const char *actual, const char *expected) {
    actual = BPSkipTypeQualifiers(actual);
    expected = BPSkipTypeQualifiers(expected);
    return actual != NULL && expected != NULL && strcmp(actual, expected) == 0;
}

static BOOL BPMethodMatches(Class cls,
                            SEL selector,
                            const char *returnType,
                            unsigned int explicitArgumentCount,
                            const char *const _Nullable explicitArgumentTypes[]) {
    Method method = class_getInstanceMethod(cls, selector);
    if (method == NULL || method_getNumberOfArguments(method) != explicitArgumentCount + 2) {
        return NO;
    }

    char *actualReturnType = method_copyReturnType(method);
    BOOL matches = BPTypesMatch(actualReturnType, returnType);
    free(actualReturnType);
    if (!matches) {
        return NO;
    }

    char *selfType = method_copyArgumentType(method, 0);
    char *selectorType = method_copyArgumentType(method, 1);
    matches = BPTypesMatch(selfType, @encode(id)) && BPTypesMatch(selectorType, @encode(SEL));
    free(selfType);
    free(selectorType);
    if (!matches) {
        return NO;
    }

    for (unsigned int index = 0; index < explicitArgumentCount; index++) {
        char *actualType = method_copyArgumentType(method, index + 2);
        matches = BPTypesMatch(actualType, explicitArgumentTypes[index]);
        free(actualType);
        if (!matches) {
            return NO;
        }
    }
    return YES;
}

static BOOL BPValidateMethod(Class cls,
                             NSString *className,
                             SEL selector,
                             const char *returnType,
                             unsigned int explicitArgumentCount,
                             const char *const _Nullable explicitArgumentTypes[],
                             NSError *__autoreleasing _Nullable *_Nullable error) {
    if (cls == Nil ||
        !BPMethodMatches(cls, selector, returnType, explicitArgumentCount,
                         explicitArgumentTypes)) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorUnsupported,
            [NSString stringWithFormat:
                @"The private Wi-Fi method %@.%@ is unavailable or has an unexpected ABI on this macOS version.",
                className, NSStringFromSelector(selector)]));
        return NO;
    }
    return YES;
}

static BOOL BPLoadAndValidateRuntime(NSError *__autoreleasing _Nullable *_Nullable error) {
    static dispatch_once_t onceToken;
    static BOOL available = NO;
    static NSError *validationError = nil;
    static void *frameworkHandle = NULL;

    dispatch_once(&onceToken, ^{
        frameworkHandle = dlopen(BPPrivateFrameworkPath.fileSystemRepresentation,
                                 RTLD_LAZY | RTLD_LOCAL);
        if (frameworkHandle == NULL) {
            const char *loaderError = dlerror();
            NSString *detail = loaderError == NULL
                ? @"unknown dynamic-loader error"
                : [NSString stringWithUTF8String:loaderError];
            validationError = BPError(
                BPPrivateWiFiErrorUnsupported,
                [NSString stringWithFormat:
                    @"The private CoreWiFi framework could not be loaded: %@.", detail]);
            return;
        }

        Class interfaceClass = NSClassFromString(@"CWInterface");
        Class networkClass = NSClassFromString(@"CWNetwork");
        Class coreInterfaceClass = NSClassFromString(@"CWFInterface");
        Class parametersClass = NSClassFromString(@"CWFAssocParameters");
        Class scanResultClass = NSClassFromString(@"CWFScanResult");
        Class networkProfileClass = NSClassFromString(@"CWFNetworkProfile");
        if (interfaceClass == Nil || networkClass == Nil || coreInterfaceClass == Nil ||
            parametersClass == Nil || scanResultClass == Nil || networkProfileClass == Nil) {
            validationError = BPError(
                BPPrivateWiFiErrorUnsupported,
                @"The private CoreWiFi association classes are unavailable on this macOS version.");
            return;
        }

        const char *objectArgument[] = {@encode(id)};
        const char *boolArgument[] = {@encode(BOOL)};
        const char *zoneArgument[] = {@encode(NSZone *)};
        // NSError ** cannot be used with @encode under ARC without an ownership
        // diagnostic. Objective-C method encodings represent the out parameter
        // as a pointer to an object; qualifiers are normalized by BPTypesMatch.
        const char *associationArguments[] = {@encode(id), "^@"};
        NSError *methodError = nil;
        if (!class_conformsToProtocol(networkProfileClass, @protocol(NSCopying)) ||
            !BPValidateMethod(interfaceClass, @"CWInterface", NSSelectorFromString(@"corewifi"),
                              @encode(id), 0, NULL, &methodError) ||
            !BPValidateMethod(networkClass, @"CWNetwork", NSSelectorFromString(@"coreWiFiScanResult"),
                              @encode(id), 0, NULL, &methodError) ||
            !BPValidateMethod(coreInterfaceClass, @"CWFInterface", NSSelectorFromString(@"serviceType"),
                              @encode(NSInteger), 0, NULL, &methodError) ||
            !BPValidateMethod(scanResultClass, @"CWFScanResult",
                              NSSelectorFromString(@"SSID"),
                              @encode(id), 0, NULL, &methodError) ||
            !BPValidateMethod(scanResultClass, @"CWFScanResult",
                              NSSelectorFromString(@"BSSID"),
                              @encode(id), 0, NULL, &methodError) ||
            !BPValidateMethod(scanResultClass, @"CWFScanResult",
                              NSSelectorFromString(@"isPSK"),
                              @encode(BOOL), 0, NULL, &methodError) ||
            !BPValidateMethod(scanResultClass, @"CWFScanResult",
                              NSSelectorFromString(@"supportedSecurityTypes"),
                              @encode(NSUInteger), 0, NULL, &methodError) ||
            !BPValidateMethod(scanResultClass, @"CWFScanResult",
                              NSSelectorFromString(@"networkProfile"),
                              @encode(id), 0, NULL, &methodError) ||
            !BPValidateMethod(networkProfileClass, @"CWFNetworkProfile",
                              @selector(copyWithZone:),
                              @encode(id), 1, zoneArgument, &methodError) ||
            !BPValidateMethod(networkProfileClass, @"CWFNetworkProfile",
                              NSSelectorFromString(@"SSID"),
                              @encode(id), 0, NULL, &methodError) ||
            !BPValidateMethod(networkProfileClass, @"CWFNetworkProfile",
                              NSSelectorFromString(@"isPSK"),
                              @encode(BOOL), 0, NULL, &methodError) ||
            !BPValidateMethod(networkProfileClass, @"CWFNetworkProfile",
                              NSSelectorFromString(@"supportedSecurityTypes"),
                              @encode(NSUInteger), 0, NULL, &methodError) ||
            !BPValidateMethod(networkProfileClass, @"CWFNetworkProfile",
                              NSSelectorFromString(@"setSystemMode:"),
                              @encode(void), 1, boolArgument, &methodError) ||
            !BPValidateMethod(networkProfileClass, @"CWFNetworkProfile",
                              NSSelectorFromString(@"isSystemMode"),
                              @encode(BOOL), 0, NULL, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters", NSSelectorFromString(@"setScanResult:"),
                              @encode(void), 1, objectArgument, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters",
                              NSSelectorFromString(@"setKnownNetworkProfile:"),
                              @encode(void), 1, objectArgument, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters", NSSelectorFromString(@"setPassword:"),
                              @encode(void), 1, objectArgument, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters", NSSelectorFromString(@"setForceBSSID:"),
                              @encode(void), 1, boolArgument, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters", NSSelectorFromString(@"setFindAndJoinNetwork:"),
                              @encode(void), 1, boolArgument, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters",
                              NSSelectorFromString(@"setRememberUponSuccessfulAssociation:"),
                              @encode(void), 1, boolArgument, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters",
                              NSSelectorFromString(@"scanResult"),
                              @encode(id), 0, NULL, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters",
                              NSSelectorFromString(@"knownNetworkProfile"),
                              @encode(id), 0, NULL, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters",
                              NSSelectorFromString(@"password"),
                              @encode(id), 0, NULL, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters",
                              NSSelectorFromString(@"forceBSSID"),
                              @encode(BOOL), 0, NULL, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters",
                              NSSelectorFromString(@"findAndJoinNetwork"),
                              @encode(BOOL), 0, NULL, &methodError) ||
            !BPValidateMethod(parametersClass, @"CWFAssocParameters",
                              NSSelectorFromString(@"rememberUponSuccessfulAssociation"),
                              @encode(BOOL), 0, NULL, &methodError) ||
            !BPValidateMethod(coreInterfaceClass, @"CWFInterface",
                              NSSelectorFromString(@"associateWithParameters:error:"),
                              @encode(BOOL), 2, associationArguments, &methodError)) {
            validationError = methodError;
            return;
        }

        available = YES;
    });

    (void)frameworkHandle;
    if (!available) {
        BPAssignError(error, validationError ?: BPError(
            BPPrivateWiFiErrorUnsupported,
            @"Strict BSSID association is unavailable on this macOS version."));
    }
    return available;
}

static BOOL BPNetworkSupportsAnySecurity(
    CWNetwork *network,
    const CWSecurity securityTypes[],
    size_t count) {
    for (size_t index = 0; index < count; index++) {
        if ([network supportsSecurity:securityTypes[index]]) {
            return YES;
        }
    }
    return NO;
}

static BPNetworkAuthenticationKind BPNetworkAuthentication(CWNetwork *network) {
    const CWSecurity personalPSKSecurityTypes[] = {
        kCWSecurityWPAPersonal,
        kCWSecurityWPAPersonalMixed,
        kCWSecurityWPA2Personal,
        kCWSecurityPersonal,
        kCWSecurityWPA3Personal,
        kCWSecurityWPA3Transition,
    };
    const CWSecurity enterpriseSecurityTypes[] = {
        kCWSecurityDynamicWEP,
        kCWSecurityWPAEnterprise,
        kCWSecurityWPAEnterpriseMixed,
        kCWSecurityWPA2Enterprise,
        kCWSecurityEnterprise,
        kCWSecurityWPA3Enterprise,
    };
    const CWSecurity passwordlessSecurityTypes[] = {
        kCWSecurityNone,
        kCWSecurityOWE,
        kCWSecurityOWETransition,
    };

    BOOL hasUnknown = [network supportsSecurity:kCWSecurityUnknown];
    BOOL hasWEP = [network supportsSecurity:kCWSecurityWEP];
    BOOL hasPersonalPSK = BPNetworkSupportsAnySecurity(
        network, personalPSKSecurityTypes,
        sizeof(personalPSKSecurityTypes) / sizeof(personalPSKSecurityTypes[0]));
    BOOL hasEnterprise = BPNetworkSupportsAnySecurity(
        network, enterpriseSecurityTypes,
        sizeof(enterpriseSecurityTypes) / sizeof(enterpriseSecurityTypes[0]));
    BOOL hasPasswordless = BPNetworkSupportsAnySecurity(
        network, passwordlessSecurityTypes,
        sizeof(passwordlessSecurityTypes) / sizeof(passwordlessSecurityTypes[0]));

    if (hasUnknown) {
        return BPNetworkAuthenticationUnknown;
    }
    if (hasWEP) {
        return BPNetworkAuthenticationWEP;
    }
    if (hasEnterprise) {
        return BPNetworkAuthenticationEnterprise;
    }
    if (hasPersonalPSK && hasPasswordless) {
        return BPNetworkAuthenticationUnknown;
    }
    if (hasPersonalPSK) {
        return BPNetworkAuthenticationPersonalPSK;
    }
    if (hasPasswordless) {
        return BPNetworkAuthenticationPasswordless;
    }
    return BPNetworkAuthenticationUnknown;
}

static NSString *_Nullable BPCanonicalBSSID(id _Nullable value) {
    if ([value isKindOfClass:NSData.class]) {
        NSData *data = value;
        if (data.length != 6) {
            return nil;
        }
        const uint8_t *bytes = data.bytes;
        return [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x",
                                          bytes[0], bytes[1], bytes[2],
                                          bytes[3], bytes[4], bytes[5]];
    }
    if (![value isKindOfClass:NSString.class]) {
        return nil;
    }

    NSString *string = [(NSString *)value lowercaseString];
    NSMutableString *hex = [NSMutableString stringWithCapacity:12];
    NSCharacterSet *hexDigits = [NSCharacterSet characterSetWithCharactersInString:
        @"0123456789abcdef"];
    for (NSUInteger index = 0; index < string.length; index++) {
        unichar character = [string characterAtIndex:index];
        if (character == ':' || character == '-') {
            continue;
        }
        if (character > 0x7f ||
            ![hexDigits characterIsMember:character]) {
            return nil;
        }
        [hex appendFormat:@"%C", character];
    }
    if (hex.length != 12) {
        return nil;
    }
    return [NSString stringWithFormat:@"%@:%@:%@:%@:%@:%@",
                                      [hex substringWithRange:NSMakeRange(0, 2)],
                                      [hex substringWithRange:NSMakeRange(2, 2)],
                                      [hex substringWithRange:NSMakeRange(4, 2)],
                                      [hex substringWithRange:NSMakeRange(6, 2)],
                                      [hex substringWithRange:NSMakeRange(8, 2)],
                                      [hex substringWithRange:NSMakeRange(10, 2)]];
}

static BOOL BPValidateScanResult(
    id scanResult,
    Class expectedScanResultClass,
    NSData *expectedSSIDData,
    NSString *expectedBSSID,
    BPNetworkAuthenticationKind authentication,
    BOOL compareSecurityTypes,
    NSUInteger expectedSecurityTypes,
    NSUInteger *_Nullable securityTypesOut,
    NSError *__autoreleasing _Nullable *_Nullable error) {
    if (scanResult == nil ||
        ![scanResult isKindOfClass:expectedScanResultClass]) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorMissingScanResult,
            @"CoreWiFi did not retain a usable private scan result."));
        return NO;
    }

    SEL ssidSelector = NSSelectorFromString(@"SSID");
    id ssid = ((BPObjectGetter)[scanResult methodForSelector:ssidSelector])(
        scanResult, ssidSelector);
    if (![ssid isKindOfClass:NSData.class] ||
        ![(NSData *)ssid isEqualToData:expectedSSIDData]) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorSSIDInvariantViolation,
            @"The private scan result does not contain the selected network's exact raw SSID."));
        return NO;
    }

    SEL bssidSelector = NSSelectorFromString(@"BSSID");
    id bssid = ((BPObjectGetter)[scanResult methodForSelector:bssidSelector])(
        scanResult, bssidSelector);
    NSString *canonicalBSSID = BPCanonicalBSSID(bssid);
    if (canonicalBSSID == nil ||
        ![canonicalBSSID isEqualToString:expectedBSSID]) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorMissingScanResult,
            @"The private scan result does not contain the selected network's exact BSSID."));
        return NO;
    }

    SEL isPSKSelector = NSSelectorFromString(@"isPSK");
    BOOL isPSK = ((BPBoolGetter)[scanResult methodForSelector:isPSKSelector])(
        scanResult, isPSKSelector);
    BOOL expectedPSK = authentication == BPNetworkAuthenticationPersonalPSK;
    if (isPSK != expectedPSK) {
        BPAssignError(error, BPError(
            compareSecurityTypes ? BPPrivateWiFiErrorUnsupported
                                 : BPPrivateWiFiErrorUnsupportedAuthentication,
            compareSecurityTypes
                ? @"CoreWiFi did not preserve the selected scan result's PSK metadata."
                : @"The private scan result's authentication family does not match the selected network."));
        return NO;
    }

    SEL securityTypesSelector = NSSelectorFromString(@"supportedSecurityTypes");
    NSUInteger securityTypes =
        ((BPUIntegerGetter)[scanResult methodForSelector:securityTypesSelector])(
            scanResult, securityTypesSelector);
    if (securityTypes == 0) {
        BPAssignError(error, BPError(
            compareSecurityTypes ? BPPrivateWiFiErrorUnsupported
                                 : BPPrivateWiFiErrorUnsupportedAuthentication,
            @"The private scan result has no usable security metadata."));
        return NO;
    }
    if (compareSecurityTypes && securityTypes != expectedSecurityTypes) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorUnsupported,
            @"CoreWiFi did not preserve the selected scan result's security metadata."));
        return NO;
    }
    if (securityTypesOut != NULL) {
        *securityTypesOut = securityTypes;
    }
    return YES;
}

static BOOL BPValidatePSKProfile(
    id profile,
    Class expectedProfileClass,
    NSData *expectedSSIDData,
    NSUInteger scanSecurityTypes,
    BOOL requireSystemMode,
    BOOL compareSecurityTypes,
    NSUInteger expectedProfileSecurityTypes,
    NSUInteger *_Nullable profileSecurityTypesOut,
    NSError *__autoreleasing _Nullable *_Nullable error) {
    if (profile == nil || ![profile isKindOfClass:expectedProfileClass]) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorCredentialDelegationUnavailable,
            @"CoreWiFi did not retain a usable request-local Wi-Fi profile."));
        return NO;
    }

    SEL ssidSelector = NSSelectorFromString(@"SSID");
    id ssid = ((BPObjectGetter)[profile methodForSelector:ssidSelector])(
        profile, ssidSelector);
    SEL isPSKSelector = NSSelectorFromString(@"isPSK");
    BOOL isPSK = ((BPBoolGetter)[profile methodForSelector:isPSKSelector])(
        profile, isPSKSelector);
    SEL securityTypesSelector = NSSelectorFromString(@"supportedSecurityTypes");
    NSUInteger securityTypes =
        ((BPUIntegerGetter)[profile methodForSelector:securityTypesSelector])(
            profile, securityTypesSelector);
    SEL systemModeSelector = NSSelectorFromString(@"isSystemMode");
    BOOL isSystemMode =
        ((BPBoolGetter)[profile methodForSelector:systemModeSelector])(
            profile, systemModeSelector);

    if (![ssid isKindOfClass:NSData.class] ||
        ![(NSData *)ssid isEqualToData:expectedSSIDData] || !isPSK ||
        securityTypes == 0 || (securityTypes & scanSecurityTypes) == 0 ||
        (requireSystemMode && !isSystemMode) ||
        (compareSecurityTypes && securityTypes != expectedProfileSecurityTypes)) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorCredentialDelegationUnavailable,
            @"CoreWiFi did not preserve compatible PSK System Keychain profile metadata."));
        return NO;
    }
    if (profileSecurityTypesOut != NULL) {
        *profileSecurityTypesOut = securityTypes;
    }
    return YES;
}

static BOOL BPValidateSSIDInvariant(
    CWInterface *interface,
    CWNetwork *network,
    NSData *expectedCurrentSSIDData,
    NSError *__autoreleasing _Nullable *_Nullable error) {
    NSData *currentSSIDData = interface.ssidData;
    NSData *targetSSIDData = network.ssidData;
    if (expectedCurrentSSIDData.length == 0 || currentSSIDData.length == 0 ||
        targetSSIDData.length == 0 ||
        ![currentSSIDData isEqualToData:expectedCurrentSSIDData] ||
        ![targetSSIDData isEqualToData:expectedCurrentSSIDData]) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorSSIDInvariantViolation,
            @"Strict BSSID requires the current connection and selected access point to have the same nonempty raw SSID supplied by the caller."));
        return NO;
    }
    return YES;
}

static id _Nullable BPCoreInterfaceForPublicInterface(
    CWInterface *interface,
    NSError *__autoreleasing _Nullable *_Nullable error) {
    if (interface == nil) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorInvalidArgument,
            @"No public CoreWLAN Wi-Fi interface is available."));
        return nil;
    }

    SEL coreWiFiSelector = NSSelectorFromString(@"corewifi");
    id coreInterface = ((BPObjectGetter)[interface methodForSelector:coreWiFiSelector])(
        interface, coreWiFiSelector);
    Class expectedInterfaceClass = NSClassFromString(@"CWFInterface");
    if (coreInterface == nil || ![coreInterface isKindOfClass:expectedInterfaceClass]) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorUnexpectedService,
            @"CoreWLAN did not provide its expected private CoreWiFi interface service."));
        return nil;
    }

    SEL serviceTypeSelector = NSSelectorFromString(@"serviceType");
    NSInteger serviceType = ((BPIntegerGetter)[coreInterface methodForSelector:serviceTypeSelector])(
        coreInterface, serviceTypeSelector);
    if (serviceType != 5) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorUnexpectedService,
            [NSString stringWithFormat:
                @"CoreWLAN returned CoreWiFi service type %ld; strict association requires service type 5.",
                (long)serviceType]));
        return nil;
    }
    return coreInterface;
}

BOOL BPPrivateBackendAvailable(NSError *__autoreleasing _Nullable *_Nullable error) {
    if (error != NULL) {
        *error = nil;
    }
    if (!BPLoadAndValidateRuntime(error)) {
        return NO;
    }

    @try {
        CWInterface *interface = [[CWWiFiClient sharedWiFiClient] interface];
        return BPCoreInterfaceForPublicInterface(interface, error) != nil;
    } @catch (NSException *exception) {
        NSString *reason = exception.reason ?: @"no exception reason was provided";
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorRuntimeException,
            [NSString stringWithFormat:
                @"Private CoreWiFi availability validation raised %@: %@.", exception.name, reason]));
        return NO;
    }
}

BOOL BPAssociateForcedBSSID(CWInterface *interface,
                            CWNetwork *network,
                            NSData *expectedCurrentSSIDData,
                            NSError *__autoreleasing _Nullable *_Nullable error) {
    if (error != NULL) {
        *error = nil;
    }
    if (interface == nil || network == nil || expectedCurrentSSIDData == nil) {
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorInvalidArgument,
            @"Strict BSSID association requires a Wi-Fi interface, a scanned network, and the expected current raw SSID."));
        return NO;
    }
    if (!BPLoadAndValidateRuntime(error)) {
        return NO;
    }

    @try {
        if (![expectedCurrentSSIDData isKindOfClass:NSData.class] ||
            expectedCurrentSSIDData.length == 0) {
            BPAssignError(error, BPError(
                BPPrivateWiFiErrorInvalidArgument,
                @"Strict BSSID association requires a nonempty expected current raw SSID."));
            return NO;
        }
        NSData *stableExpectedSSIDData = [expectedCurrentSSIDData copy];

        id coreInterface = BPCoreInterfaceForPublicInterface(interface, error);
        if (coreInterface == nil) {
            return NO;
        }
        if (!BPValidateSSIDInvariant(interface, network, stableExpectedSSIDData, error)) {
            return NO;
        }

        BPNetworkAuthenticationKind authentication = BPNetworkAuthentication(network);
        switch (authentication) {
            case BPNetworkAuthenticationPasswordless:
            case BPNetworkAuthenticationPersonalPSK:
                break;
            case BPNetworkAuthenticationWEP:
                BPAssignError(error, BPError(
                    BPPrivateWiFiErrorUnsupportedAuthentication,
                    @"Credentialless Strict BSSID does not support WEP networks."));
                return NO;
            case BPNetworkAuthenticationEnterprise:
                BPAssignError(error, BPError(
                    BPPrivateWiFiErrorUnsupportedAuthentication,
                    @"Strict BSSID does not support Enterprise or 802.1X networks."));
                return NO;
            case BPNetworkAuthenticationUnknown:
                BPAssignError(error, BPError(
                    BPPrivateWiFiErrorUnsupportedAuthentication,
                    @"Strict BSSID refused a network whose authentication is unknown, unsupported, or ambiguous."));
                return NO;
        }

        SEL scanResultSelector = NSSelectorFromString(@"coreWiFiScanResult");
        id scanResult = ((BPObjectGetter)[network methodForSelector:scanResultSelector])(
            network, scanResultSelector);
        Class expectedScanResultClass = NSClassFromString(@"CWFScanResult");
        if (scanResult == nil || ![scanResult isKindOfClass:expectedScanResultClass]) {
            BPAssignError(error, BPError(
                BPPrivateWiFiErrorMissingScanResult,
                @"The selected CoreWLAN network has no usable private scan result. Scan again and retry."));
            return NO;
        }

        NSString *targetBSSID = BPCanonicalBSSID(network.bssid);
        if (targetBSSID == nil) {
            BPAssignError(error, BPError(
                BPPrivateWiFiErrorMissingScanResult,
                @"The selected CoreWLAN network has no usable BSSID."));
            return NO;
        }
        NSUInteger scanSecurityTypes = 0;
        if (!BPValidateScanResult(
                scanResult, expectedScanResultClass, stableExpectedSSIDData,
                targetBSSID, authentication, NO, 0, &scanSecurityTypes, error)) {
            return NO;
        }

        Class expectedProfileClass = NSClassFromString(@"CWFNetworkProfile");
        id systemKeychainProfile = nil;
        NSUInteger profileSecurityTypes = 0;
        if (authentication == BPNetworkAuthenticationPersonalPSK) {
            // CWFScanResult provides profile metadata for this exact scan
            // result. It can return a shared matching profile or construct one
            // from scan fields, so it must remain unmodified. A request-local
            // copy marked as system mode makes airportd perform the System
            // Keychain lookup itself; no password is returned to this process.
            SEL networkProfileSelector = NSSelectorFromString(@"networkProfile");
            id baseProfile =
                ((BPObjectGetter)[scanResult methodForSelector:networkProfileSelector])(
                    scanResult, networkProfileSelector);
            if (!BPValidatePSKProfile(
                    baseProfile, expectedProfileClass, stableExpectedSSIDData,
                    scanSecurityTypes, NO, NO, 0, &profileSecurityTypes,
                    error)) {
                return NO;
            }

            SEL systemModeSelector = NSSelectorFromString(@"isSystemMode");
            BOOL baseWasSystemMode =
                ((BPBoolGetter)[baseProfile methodForSelector:systemModeSelector])(
                    baseProfile, systemModeSelector);

            // Do not mutate an object owned by the scan result. An independent
            // copy prevents system-mode state from leaking into saved or cached
            // profile metadata.
            systemKeychainProfile = [baseProfile copy];
            if (systemKeychainProfile == nil ||
                ![systemKeychainProfile isKindOfClass:expectedProfileClass] ||
                systemKeychainProfile == baseProfile) {
                BPAssignError(error, BPError(
                    BPPrivateWiFiErrorCredentialDelegationUnavailable,
                    @"CoreWiFi could not copy the request-local profile needed for airportd credential resolution."));
                return NO;
            }

            SEL systemModeSetter = NSSelectorFromString(@"setSystemMode:");
            ((BPBoolSetter)[systemKeychainProfile methodForSelector:systemModeSetter])(
                systemKeychainProfile, systemModeSetter, YES);
            BOOL baseIsStillUnchanged =
                ((BPBoolGetter)[baseProfile methodForSelector:systemModeSelector])(
                    baseProfile, systemModeSelector) == baseWasSystemMode;
            if (!baseIsStillUnchanged ||
                !BPValidatePSKProfile(
                    systemKeychainProfile, expectedProfileClass,
                    stableExpectedSSIDData, scanSecurityTypes, YES, YES,
                    profileSecurityTypes, NULL, error)) {
                if (!baseIsStillUnchanged) {
                    BPAssignError(error, BPError(
                        BPPrivateWiFiErrorCredentialDelegationUnavailable,
                        @"CoreWiFi mutated shared profile metadata while preparing the System Keychain request."));
                }
                return NO;
            }
        }

        Class parametersClass = NSClassFromString(@"CWFAssocParameters");
        id parameters = [[parametersClass alloc] init];
        if (parameters == nil || ![parameters isKindOfClass:parametersClass]) {
            BPAssignError(error, BPError(
                BPPrivateWiFiErrorUnsupported,
                @"The private CoreWiFi association-parameters object could not be created."));
            return NO;
        }

        SEL scanResultSetter = NSSelectorFromString(@"setScanResult:");
        ((BPObjectSetter)[parameters methodForSelector:scanResultSetter])(
            parameters, scanResultSetter, scanResult);

        SEL knownProfileSetter = NSSelectorFromString(@"setKnownNetworkProfile:");
        ((BPObjectSetter)[parameters methodForSelector:knownProfileSetter])(
            parameters, knownProfileSetter, systemKeychainProfile);

        SEL passwordSetter = NSSelectorFromString(@"setPassword:");
        ((BPObjectSetter)[parameters methodForSelector:passwordSetter])(
            parameters, passwordSetter, nil);

        SEL forceSetter = NSSelectorFromString(@"setForceBSSID:");
        ((BPBoolSetter)[parameters methodForSelector:forceSetter])(
            parameters, forceSetter, YES);

        SEL findAndJoinSetter = NSSelectorFromString(@"setFindAndJoinNetwork:");
        ((BPBoolSetter)[parameters methodForSelector:findAndJoinSetter])(
            parameters, findAndJoinSetter, NO);

        SEL rememberSetter = NSSelectorFromString(@"setRememberUponSuccessfulAssociation:");
        ((BPBoolSetter)[parameters methodForSelector:rememberSetter])(
            parameters, rememberSetter, NO);

        // Association-parameter object properties use copy semantics. Validate
        // the actual request-owned values rather than the objects supplied to
        // the setters before allowing them to cross the XPC boundary.
        SEL storedScanSelector = NSSelectorFromString(@"scanResult");
        id storedScanResult =
            ((BPObjectGetter)[parameters methodForSelector:storedScanSelector])(
                parameters, storedScanSelector);
        if (!BPValidateScanResult(
                storedScanResult, expectedScanResultClass,
                stableExpectedSSIDData, targetBSSID, authentication, YES,
                scanSecurityTypes, NULL, error)) {
            return NO;
        }

        SEL storedProfileSelector = NSSelectorFromString(@"knownNetworkProfile");
        id storedProfile =
            ((BPObjectGetter)[parameters methodForSelector:storedProfileSelector])(
                parameters, storedProfileSelector);
        if (authentication == BPNetworkAuthenticationPersonalPSK) {
            if (!BPValidatePSKProfile(
                    storedProfile, expectedProfileClass, stableExpectedSSIDData,
                    scanSecurityTypes, YES, YES, profileSecurityTypes, NULL,
                    error)) {
                return NO;
            }
        } else if (storedProfile != nil) {
            BPAssignError(error, BPError(
                BPPrivateWiFiErrorUnsupported,
                @"CoreWiFi unexpectedly retained a known-network profile for a passwordless request."));
            return NO;
        }

        SEL storedPasswordSelector = NSSelectorFromString(@"password");
        id storedPassword =
            ((BPObjectGetter)[parameters methodForSelector:storedPasswordSelector])(
                parameters, storedPasswordSelector);
        SEL storedForceSelector = NSSelectorFromString(@"forceBSSID");
        BOOL storedForce =
            ((BPBoolGetter)[parameters methodForSelector:storedForceSelector])(
                parameters, storedForceSelector);
        SEL storedFindAndJoinSelector = NSSelectorFromString(@"findAndJoinNetwork");
        BOOL storedFindAndJoin =
            ((BPBoolGetter)[parameters methodForSelector:storedFindAndJoinSelector])(
                parameters, storedFindAndJoinSelector);
        SEL storedRememberSelector =
            NSSelectorFromString(@"rememberUponSuccessfulAssociation");
        BOOL storedRemember =
            ((BPBoolGetter)[parameters methodForSelector:storedRememberSelector])(
                parameters, storedRememberSelector);
        if (storedPassword != nil || !storedForce || storedFindAndJoin ||
            storedRemember) {
            BPAssignError(error, BPError(
                BPPrivateWiFiErrorUnsupported,
                @"CoreWiFi did not preserve the strict association parameters."));
            return NO;
        }

        SEL associateSelector = NSSelectorFromString(@"associateWithParameters:error:");
        if (!BPValidateSSIDInvariant(interface, network, stableExpectedSSIDData, error)) {
            return NO;
        }
        NSError *associationError = nil;
        BOOL associated = ((BPAssociateFunction)[coreInterface methodForSelector:associateSelector])(
            coreInterface, associateSelector, parameters, &associationError);
        if (!associated) {
            NSString *description = associationError == nil
                ? @"CoreWiFi rejected the strict BSSID association without returning an error."
                : [NSString stringWithFormat:
                    @"CoreWiFi rejected the strict BSSID association: %@",
                    associationError.localizedDescription];
            BPAssignError(error, BPErrorWithUnderlying(
                BPPrivateWiFiErrorAssociationFailed,
                description,
                associationError));
            return NO;
        }
        return YES;
    } @catch (NSException *exception) {
        NSString *reason = exception.reason ?: @"no exception reason was provided";
        BPAssignError(error, BPError(
            BPPrivateWiFiErrorRuntimeException,
            [NSString stringWithFormat:
                @"The private CoreWiFi association call raised %@: %@.", exception.name, reason]));
        return NO;
    }
}
