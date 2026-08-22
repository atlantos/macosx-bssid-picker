// SPDX-License-Identifier: GPL-3.0-only

#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <Security/SecTrustSettings.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Setup-only guardrail for the legacy macOS private-key ACL workflow.
 * It binds a certificate fingerprint to the corresponding private-key record
 * using the public-key application label, proves the key's system-assigned
 * text label is an unambiguous selector, and verifies the ACL produced by
 * security import/set-key-partition-list. It never reads or uses private-key
 * material.
 */

static int fail_message(const char *message)
{
    fprintf(stderr, "signing-key-helper: %s\n", message);
    return 1;
}

static int fail_status(const char *operation, OSStatus status)
{
    CFStringRef message = SecCopyErrorMessageString(status, NULL);
    char buffer[512] = "unknown error";
    if (message != NULL) {
        (void)CFStringGetCString(message, buffer, sizeof(buffer), kCFStringEncodingUTF8);
        CFRelease(message);
    }
    fprintf(stderr, "signing-key-helper: %s: %s (OSStatus %d)\n",
            operation, buffer, (int)status);
    return 1;
}

static int hex_nibble(char character)
{
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

static bool parse_sha1(const char *text, unsigned char digest[CC_SHA1_DIGEST_LENGTH])
{
    if (strlen(text) != CC_SHA1_DIGEST_LENGTH * 2) {
        return false;
    }
    for (size_t index = 0; index < CC_SHA1_DIGEST_LENGTH; index++) {
        int high = hex_nibble(text[index * 2]);
        int low = hex_nibble(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        digest[index] = (unsigned char)((high << 4) | low);
    }
    return true;
}

static CFMutableDictionaryRef new_query(CFTypeRef item_class, SecKeychainRef keychain)
{
    const void *keychain_values[] = {keychain};
    CFArrayRef keychains = CFArrayCreate(NULL, keychain_values, 1, &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (keychains == NULL || query == NULL) {
        if (keychains != NULL) CFRelease(keychains);
        if (query != NULL) CFRelease(query);
        return NULL;
    }
    CFDictionarySetValue(query, kSecClass, item_class);
    CFDictionarySetValue(query, kSecMatchSearchList, keychains);
    CFRelease(keychains);
    return query;
}

static OSStatus copy_all_matches(CFMutableDictionaryRef query, CFArrayRef *matches)
{
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    if (status == errSecItemNotFound) {
        *matches = CFArrayCreate(NULL, NULL, 0, &kCFTypeArrayCallBacks);
        return *matches == NULL ? errSecAllocate : errSecSuccess;
    }
    if (status != errSecSuccess) {
        return status;
    }
    if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
        if (result != NULL) CFRelease(result);
        return errSecInternalComponent;
    }
    *matches = (CFArrayRef)result;
    return errSecSuccess;
}

static OSStatus copy_all_attribute_matches(CFMutableDictionaryRef query, CFArrayRef *matches)
{
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    if (status == errSecItemNotFound) {
        *matches = CFArrayCreate(NULL, NULL, 0, &kCFTypeArrayCallBacks);
        return *matches == NULL ? errSecAllocate : errSecSuccess;
    }
    if (status != errSecSuccess) {
        return status;
    }
    if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
        if (result != NULL) CFRelease(result);
        return errSecInternalComponent;
    }
    *matches = (CFArrayRef)result;
    return errSecSuccess;
}

static OSStatus find_certificate(SecKeychainRef keychain,
                                 const unsigned char expected[CC_SHA1_DIGEST_LENGTH],
                                 SecCertificateRef *certificate)
{
    CFMutableDictionaryRef query = new_query(kSecClassCertificate, keychain);
    if (query == NULL) return errSecAllocate;
    CFArrayRef matches = NULL;
    OSStatus status = copy_all_matches(query, &matches);
    CFRelease(query);
    if (status != errSecSuccess) return status;

    CFIndex found = 0;
    SecCertificateRef selected = NULL;
    for (CFIndex index = 0; index < CFArrayGetCount(matches); index++) {
        SecCertificateRef candidate = (SecCertificateRef)CFArrayGetValueAtIndex(matches, index);
        CFDataRef data = SecCertificateCopyData(candidate);
        unsigned char actual[CC_SHA1_DIGEST_LENGTH];
        if (data != NULL) {
            CC_SHA1(CFDataGetBytePtr(data), (CC_LONG)CFDataGetLength(data), actual);
            if (memcmp(actual, expected, sizeof(actual)) == 0) {
                selected = candidate;
                found++;
            }
            CFRelease(data);
        }
    }
    if (found == 1) CFRetain(selected);
    CFRelease(matches);
    if (found == 0) return errSecItemNotFound;
    if (found != 1) return errSecDuplicateItem;
    *certificate = selected;
    return errSecSuccess;
}

static CFDataRef copy_key_identifier(SecKeyRef key)
{
    CFDictionaryRef attributes = SecKeyCopyAttributes(key);
    if (attributes == NULL) return NULL;
    CFTypeRef value = CFDictionaryGetValue(attributes, kSecAttrApplicationLabel);
    CFDataRef identifier = NULL;
    if (value != NULL && CFGetTypeID(value) == CFDataGetTypeID()) {
        identifier = CFRetain(value);
    }
    CFRelease(attributes);
    return identifier;
}

static bool same_key(SecKeyRef first, SecKeyRef second)
{
    CFDataRef first_id = copy_key_identifier(first);
    CFDataRef second_id = copy_key_identifier(second);
    bool result = first_id != NULL && second_id != NULL && CFEqual(first_id, second_id);
    if (first_id != NULL) CFRelease(first_id);
    if (second_id != NULL) CFRelease(second_id);
    return result;
}

static OSStatus copy_private_key_for_certificate(SecKeychainRef keychain,
                                                 SecCertificateRef certificate,
                                                 SecKeyRef *private_key)
{
    /*
     * Do not use SecIdentityCopyPrivateKey here. On macOS that legacy API can
     * authorize access to the private key while merely resolving an identity,
     * which produces an unnecessary Keychain password dialog during setup.
     *
     * kSecAttrApplicationLabel is documented as the public-key hash for both
     * public and private keys. Deriving it from the certificate's public key
     * therefore identifies the matching private key without using its secret
     * material or exercising its signing ACL.
     */
    SecKeyRef public_key = SecCertificateCopyKey(certificate);
    if (public_key == NULL) return errSecDecode;
    CFDataRef identifier = copy_key_identifier(public_key);
    CFRelease(public_key);
    if (identifier == NULL) return errSecNoSuchAttr;

    CFMutableDictionaryRef query = new_query(kSecClassKey, keychain);
    if (query == NULL) {
        CFRelease(identifier);
        return errSecAllocate;
    }
    CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(query, kSecAttrApplicationLabel, identifier);
    CFRelease(identifier);

    CFArrayRef matches = NULL;
    OSStatus status = copy_all_matches(query, &matches);
    CFRelease(query);
    if (status != errSecSuccess) return status;

    CFIndex count = CFArrayGetCount(matches);
    if (count != 1) {
        CFRelease(matches);
        return count == 0 ? errSecItemNotFound : errSecDuplicateItem;
    }
    SecKeyRef selected = (SecKeyRef)CFArrayGetValueAtIndex(matches, 0);
    CFRetain(selected);
    CFRelease(matches);
    *private_key = selected;
    return errSecSuccess;
}

static OSStatus copy_keys_with_label(SecKeychainRef keychain, CFStringRef label,
                                     CFArrayRef *matches)
{
    CFMutableDictionaryRef query = new_query(kSecClassKey, keychain);
    if (query == NULL) return errSecAllocate;
    CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(query, kSecAttrCanSign, kCFBooleanTrue);
    if (label != NULL) {
        CFDictionarySetValue(query, kSecAttrLabel, label);
    }
    OSStatus status = copy_all_matches(query, matches);
    CFRelease(query);
    return status;
}

static OSStatus copy_key_attributes_with_label(SecKeychainRef keychain,
                                               CFStringRef label,
                                               CFDataRef application_label,
                                               CFArrayRef *matches)
{
    CFMutableDictionaryRef query = new_query(kSecClassKey, keychain);
    if (query == NULL) return errSecAllocate;
    CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    if (label != NULL) {
        CFDictionarySetValue(query, kSecAttrLabel, label);
    }
    if (application_label != NULL) {
        CFDictionarySetValue(query, kSecAttrApplicationLabel, application_label);
    }
    OSStatus status = copy_all_attribute_matches(query, matches);
    CFRelease(query);
    return status;
}

static int select_private_key_label(SecKeychainRef keychain,
                                    SecCertificateRef certificate,
                                    CFStringRef *selected_label)
{
    /*
     * This check deliberately requests attributes, never a SecKeyRef. A live
     * private-key reference can trigger its item-access dialog before the
     * partition ACL has been installed. PKCS#12 friendlyName is not reliably
     * imported as kSecAttrLabel, so discover the system-assigned label and
     * prove that the exact selector accepted by security(1) is unique.
     */
    SecKeyRef public_key = SecCertificateCopyKey(certificate);
    if (public_key == NULL) {
        return fail_message("could not copy the certificate's public key");
    }
    CFDataRef identifier = copy_key_identifier(public_key);
    CFRelease(public_key);
    if (identifier == NULL) {
        return fail_message("could not derive the certificate public-key hash");
    }

    CFArrayRef matches = NULL;
    OSStatus status = copy_key_attributes_with_label(
        keychain, NULL, identifier, &matches);
    if (status != errSecSuccess) {
        CFRelease(identifier);
        return fail_status("query the exact private-key metadata", status);
    }
    if (CFArrayGetCount(matches) != 1) {
        CFIndex count = CFArrayGetCount(matches);
        CFRelease(matches);
        CFRelease(identifier);
        return fail_message(count == 0
            ? "the imported certificate has no matching private key"
            : "the certificate public-key hash resolves to more than one private key");
    }

    CFTypeRef item = CFArrayGetValueAtIndex(matches, 0);
    bool valid = item != NULL && CFGetTypeID(item) == CFDictionaryGetTypeID();
    if (valid) {
        CFDictionaryRef attributes = (CFDictionaryRef)item;
        CFTypeRef actual_label = CFDictionaryGetValue(attributes, kSecAttrLabel);
        CFTypeRef actual_identifier =
            CFDictionaryGetValue(attributes, kSecAttrApplicationLabel);
        CFTypeRef key_class = CFDictionaryGetValue(attributes, kSecAttrKeyClass);
        CFTypeRef can_sign = CFDictionaryGetValue(attributes, kSecAttrCanSign);
        valid = actual_label != NULL && CFGetTypeID(actual_label) == CFStringGetTypeID() &&
            CFStringGetLength((CFStringRef)actual_label) > 0 &&
            actual_identifier != NULL && CFEqual(actual_identifier, identifier) &&
            key_class != NULL && CFEqual(key_class, kSecAttrKeyClassPrivate) &&
            can_sign != NULL && CFEqual(can_sign, kCFBooleanTrue);
        if (valid) CFRetain(actual_label);
        *selected_label = valid ? (CFStringRef)actual_label : NULL;
    }
    CFRelease(matches);
    if (!valid) {
        CFRelease(identifier);
        return fail_message(
            "the imported private-key metadata does not match the generated identity");
    }

    /* security set-key-partition-list can match this key only by text label. */
    matches = NULL;
    status = copy_key_attributes_with_label(
        keychain, *selected_label, NULL, &matches);
    if (status != errSecSuccess) {
        CFRelease(*selected_label);
        *selected_label = NULL;
        CFRelease(identifier);
        return fail_status("verify the private-key label selector", status);
    }
    bool unique = CFArrayGetCount(matches) == 1;
    if (unique) {
        CFTypeRef candidate = CFArrayGetValueAtIndex(matches, 0);
        unique = candidate != NULL && CFGetTypeID(candidate) == CFDictionaryGetTypeID();
        if (unique) {
            CFTypeRef candidate_id = CFDictionaryGetValue(
                (CFDictionaryRef)candidate, kSecAttrApplicationLabel);
            CFTypeRef can_sign = CFDictionaryGetValue(
                (CFDictionaryRef)candidate, kSecAttrCanSign);
            unique = candidate_id != NULL && CFEqual(candidate_id, identifier) &&
                can_sign != NULL && CFEqual(can_sign, kCFBooleanTrue);
        }
    }
    CFRelease(matches);
    CFRelease(identifier);
    if (!unique) {
        CFRelease(*selected_label);
        *selected_label = NULL;
        return fail_message(
            "the imported key's system label is not unique among signing private keys");
    }
    return 0;
}

static int validate_key_attributes(SecKeyRef key)
{
    CFDictionaryRef attributes = SecKeyCopyAttributes(key);
    if (attributes == NULL) return fail_message("could not read private-key attributes");
    CFTypeRef key_class = CFDictionaryGetValue(attributes, kSecAttrKeyClass);
    CFTypeRef can_sign_value = CFDictionaryGetValue(attributes, kSecAttrCanSign);
    bool is_private = key_class != NULL && CFEqual(key_class, kSecAttrKeyClassPrivate);
    bool can_sign = can_sign_value != NULL && CFEqual(can_sign_value, kCFBooleanTrue);
    CFRelease(attributes);
    if (!is_private) return fail_message("the certificate does not resolve to a private key");
    if (!can_sign) return fail_message("the certificate's private key cannot sign");
    return 0;
}

static int validate_unique_resolution(SecKeychainRef keychain, SecKeyRef expected,
                                      CFStringRef label, bool allow_missing)
{
    CFArrayRef matches = NULL;
    OSStatus status = copy_keys_with_label(keychain, label, &matches);
    if (status != errSecSuccess) return fail_status("search for the private-key label", status);
    CFIndex count = CFArrayGetCount(matches);
    if (count == 0 && allow_missing) {
        CFRelease(matches);
        return 0;
    }
    if (count != 1) {
        CFRelease(matches);
        return fail_message(count == 0
            ? "the unique private-key label does not resolve to a key"
            : "the unique private-key label resolves to more than one key");
    }
    SecKeyRef resolved = (SecKeyRef)CFArrayGetValueAtIndex(matches, 0);
    bool equal = same_key(expected, resolved);
    CFRelease(matches);
    return equal ? 0 : fail_message("the unique private-key label belongs to a different key");
}

static bool authorization_present(CFArrayRef authorizations, CFStringRef wanted)
{
    return authorizations != NULL && CFArrayContainsValue(
        authorizations, CFRangeMake(0, CFArrayGetCount(authorizations)), wanted);
}

static bool trusted_application_is_codesign(SecTrustedApplicationRef application)
{
    CFDataRef data = NULL;
    if (SecTrustedApplicationCopyData(application, &data) != errSecSuccess || data == NULL) {
        return false;
    }
    const char expected[] = "/usr/bin/codesign";
    CFIndex length = CFDataGetLength(data);
    const UInt8 *bytes = CFDataGetBytePtr(data);
    bool matches = (length == (CFIndex)strlen(expected) ||
                    (length == (CFIndex)strlen(expected) + 1 && bytes[length - 1] == 0)) &&
                   memcmp(bytes, expected, strlen(expected)) == 0;
    CFRelease(data);
    return matches;
}

static int hex_nibble_utf16(UniChar character)
{
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

static CFDataRef copy_data_from_hex(CFStringRef text)
{
    if (text == NULL) return NULL;
    CFIndex text_length = CFStringGetLength(text);
    if (text_length == 0 || text_length % 2 != 0) return NULL;

    CFIndex byte_count = text_length / 2;
    UInt8 *bytes = calloc((size_t)byte_count, sizeof(*bytes));
    if (bytes == NULL) return NULL;
    for (CFIndex index = 0; index < byte_count; index++) {
        int high = hex_nibble_utf16(CFStringGetCharacterAtIndex(text, index * 2));
        int low = hex_nibble_utf16(CFStringGetCharacterAtIndex(text, index * 2 + 1));
        if (high < 0 || low < 0) {
            free(bytes);
            return NULL;
        }
        bytes[index] = (UInt8)((high << 4) | low);
    }

    CFDataRef data = CFDataCreate(NULL, bytes, byte_count);
    free(bytes);
    return data;
}

static bool partition_description_is_exact(CFStringRef description)
{
    CFDataRef encoded = copy_data_from_hex(description);
    if (encoded == NULL) return false;
    CFErrorRef error = NULL;
    CFPropertyListRef property_list = CFPropertyListCreateWithData(
        NULL, encoded, kCFPropertyListImmutable, NULL, &error);
    CFRelease(encoded);
    if (error != NULL) CFRelease(error);
    if (property_list == NULL || CFGetTypeID(property_list) != CFDictionaryGetTypeID()) {
        if (property_list != NULL) CFRelease(property_list);
        return false;
    }

    CFTypeRef value = CFDictionaryGetValue((CFDictionaryRef)property_list, CFSTR("Partitions"));
    if (value == NULL || CFGetTypeID(value) != CFArrayGetTypeID()) {
        CFRelease(property_list);
        return false;
    }
    CFArrayRef partitions = (CFArrayRef)value;
    if (CFDictionaryGetCount((CFDictionaryRef)property_list) != 1 ||
        CFArrayGetCount(partitions) != 2) {
        CFRelease(property_list);
        return false;
    }

    bool apple = false;
    bool apple_tool = false;
    for (CFIndex index = 0; index < 2; index++) {
        CFTypeRef partition = CFArrayGetValueAtIndex(partitions, index);
        if (partition == NULL || CFGetTypeID(partition) != CFStringGetTypeID()) {
            CFRelease(property_list);
            return false;
        }
        if (CFEqual(partition, CFSTR("apple:"))) apple = true;
        else if (CFEqual(partition, CFSTR("apple-tool:"))) apple_tool = true;
        else {
            CFRelease(property_list);
            return false;
        }
    }
    CFRelease(property_list);
    return apple && apple_tool;
}

static int verify_acl(SecKeyRef key)
{
    SecAccessRef access = NULL;
    OSStatus status = SecKeychainItemCopyAccess((SecKeychainItemRef)key, &access);
    if (status != errSecSuccess) {
        return fail_status("read the private-key access controls", status);
    }
    CFArrayRef acls = NULL;
    status = SecAccessCopyACLList(access, &acls);
    CFRelease(access);
    if (status != errSecSuccess) {
        return fail_status("list the private-key access controls", status);
    }

    CFIndex signing_acl_count = 0;
    CFIndex partition_acl_count = 0;
    bool signing_acl_valid = false;
    bool partition_acl_valid = false;
    for (CFIndex index = 0; index < CFArrayGetCount(acls); index++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, index);
        CFArrayRef authorizations = SecACLCopyAuthorizations(acl);
        bool is_any = authorization_present(authorizations, kSecACLAuthorizationAny);
        bool is_signing = authorization_present(authorizations, kSecACLAuthorizationSign);
        bool is_partition = authorization_present(authorizations, kSecACLAuthorizationPartitionID);
        if (is_any) signing_acl_count++;
        if (is_signing) signing_acl_count++;

        if (is_any || is_signing || is_partition) {
            CFArrayRef applications = NULL;
            CFStringRef description = NULL;
            SecKeychainPromptSelector prompt = 0;
            status = SecACLCopyContents(acl, &applications, &description, &prompt);
            if (status != errSecSuccess) {
                if (authorizations != NULL) CFRelease(authorizations);
                CFRelease(acls);
                return fail_status("inspect a private-key access-control entry", status);
            }
            if (is_signing && !is_any && applications != NULL &&
                CFArrayGetCount(applications) == 1 &&
                (prompt & kSecKeychainPromptRequirePassphase) == 0 &&
                trusted_application_is_codesign((SecTrustedApplicationRef)
                    CFArrayGetValueAtIndex(applications, 0))) {
                signing_acl_valid = true;
            }
            if (is_partition) {
                partition_acl_count++;
                partition_acl_valid = authorizations != NULL &&
                    CFArrayGetCount(authorizations) == 1 &&
                    applications == NULL &&
                    (prompt & kSecKeychainPromptRequirePassphase) == 0 &&
                    partition_description_is_exact(description);
            }
            if (applications != NULL) CFRelease(applications);
            if (description != NULL) CFRelease(description);
        }
        if (authorizations != NULL) CFRelease(authorizations);
    }
    CFRelease(acls);

    if (signing_acl_count != 1 || !signing_acl_valid) {
        return fail_message("the signing ACL must trust only /usr/bin/codesign");
    }
    if (partition_acl_count != 1 || !partition_acl_valid) {
        return fail_message("the partition ACL must contain exactly apple-tool: and apple:");
    }
    return 0;
}

static int verify_code_signing_only_trust(SecCertificateRef certificate)
{
    CFArrayRef settings = NULL;
    OSStatus status = SecTrustSettingsCopyTrustSettings(
        certificate, kSecTrustSettingsDomainUser, &settings);
    if (status != errSecSuccess) {
        return fail_status("read the certificate's per-user trust settings", status);
    }

    bool valid = settings != NULL && CFGetTypeID(settings) == CFArrayGetTypeID() &&
        CFArrayGetCount(settings) == 1;
    CFDictionaryRef constraint = NULL;
    if (valid) {
        CFTypeRef value = CFArrayGetValueAtIndex(settings, 0);
        valid = value != NULL && CFGetTypeID(value) == CFDictionaryGetTypeID();
        if (valid) constraint = (CFDictionaryRef)value;
    }

    SecPolicyRef policy = NULL;
    if (valid) {
        /*
         * `security add-trusted-cert -r trustRoot -p codeSign` writes one
         * constraint containing the Code Signing policy. Current macOS also
         * returns its redundant policy-name metadata. TrustRoot is represented
         * by the documented absence of kSecTrustSettingsResult.
         */
        CFIndex count = CFDictionaryGetCount(constraint);
        CFTypeRef value = CFDictionaryGetValue(constraint, kSecTrustSettingsPolicy);
        CFTypeRef policy_name = CFDictionaryGetValue(
            constraint, CFSTR("kSecTrustSettingsPolicyName"));
        bool policy_name_valid = policy_name == NULL ||
            (CFGetTypeID(policy_name) == CFStringGetTypeID() &&
             CFEqual(policy_name, CFSTR("CodeSigning")));
        valid = (count == 1 || (count == 2 && policy_name != NULL)) &&
            policy_name_valid && value != NULL &&
            CFGetTypeID(value) == SecPolicyGetTypeID();
        if (valid) policy = (SecPolicyRef)value;
    }

    CFDictionaryRef properties = NULL;
    if (valid) {
        properties = SecPolicyCopyProperties(policy);
        valid = properties != NULL;
    }
    if (valid) {
        CFTypeRef oid = CFDictionaryGetValue(properties, kSecPolicyOid);
        valid = oid != NULL && CFGetTypeID(oid) == CFStringGetTypeID() &&
            CFEqual(oid, kSecPolicyAppleCodeSigning);
    }

    if (properties != NULL) CFRelease(properties);
    if (settings != NULL) CFRelease(settings);
    return valid ? 0 : fail_message(
        "per-user trust must contain exactly one Code Signing-only TrustRoot constraint");
}

int main(int argc, char *argv[])
{
    bool label_exists_mode = argc == 4 && strcmp(argv[1], "label-exists") == 0;
    bool trust_mode = argc == 4 && strcmp(argv[1], "verify-trust") == 0;
    bool select_mode = argc == 4 && strcmp(argv[1], "select-label") == 0;
    bool identity_mode = argc == 5 && strcmp(argv[1], "verify") == 0;
    if (!label_exists_mode && !trust_mode && !select_mode && !identity_mode) {
        fprintf(stderr,
            "usage: signing-key-helper verify login-keychain-path cert-sha1 private-key-label\n"
            "       signing-key-helper select-label login-keychain-path cert-sha1\n"
            "       signing-key-helper verify-trust login-keychain-path cert-sha1\n"
            "       signing-key-helper label-exists login-keychain-path unique-key-label\n");
        return 64;
    }
    unsigned char expected_sha1[CC_SHA1_DIGEST_LENGTH];
    if ((identity_mode || trust_mode || select_mode) &&
        !parse_sha1(argv[3], expected_sha1)) {
        return fail_message("certificate SHA-1 must be 40 hexadecimal characters");
    }
    CFStringRef label = NULL;
    if (label_exists_mode || identity_mode) {
        const char *label_text = label_exists_mode ? argv[3] : argv[4];
        label = CFStringCreateWithCString(NULL, label_text, kCFStringEncodingUTF8);
        if (label == NULL || CFStringGetLength(label) == 0) {
            if (label != NULL) CFRelease(label);
            return fail_message("the unique private-key label is empty or invalid UTF-8");
        }
    }

    SecKeychainRef keychain = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    OSStatus status = SecKeychainOpen(argv[2], &keychain);
#pragma clang diagnostic pop
    if (status != errSecSuccess) {
        if (label != NULL) CFRelease(label);
        return fail_status("open the specified login Keychain", status);
    }

    if (label_exists_mode) {
        CFArrayRef matches = NULL;
        status = copy_key_attributes_with_label(keychain, label, NULL, &matches);
        if (status != errSecSuccess) {
            CFRelease(keychain);
            CFRelease(label);
            return fail_status("query the private-key label", status);
        }
        CFIndex count = CFArrayGetCount(matches);
        CFRelease(matches);
        CFRelease(keychain);
        CFRelease(label);
        if (count == 0) return 2;
        printf("Found %ld private key(s) with the label.\n", (long)count);
        return 0;
    }

    SecCertificateRef certificate = NULL;
    status = find_certificate(keychain, expected_sha1, &certificate);
    if (status != errSecSuccess) {
        CFRelease(keychain);
        if (label != NULL) CFRelease(label);
        return fail_status("resolve exactly one certificate by SHA-1 in the specified Keychain", status);
    }
    if (trust_mode) {
        int result = verify_code_signing_only_trust(certificate);
        CFRelease(certificate);
        CFRelease(keychain);
        if (result == 0) {
            printf("Code Signing-only per-user trust verification succeeded.\n");
        }
        return result;
    }
    if (select_mode) {
        CFStringRef selected_label = NULL;
        int result = select_private_key_label(keychain, certificate, &selected_label);
        CFRelease(certificate);
        CFRelease(keychain);
        if (result == 0) {
            CFIndex capacity = CFStringGetMaximumSizeForEncoding(
                CFStringGetLength(selected_label), kCFStringEncodingUTF8) + 1;
            if (capacity <= 1 || capacity > 4096) {
                result = fail_message("the private-key label has an unsafe length");
            } else {
                char *buffer = calloc((size_t)capacity, sizeof(*buffer));
                if (buffer == NULL || !CFStringGetCString(
                        selected_label, buffer, capacity, kCFStringEncodingUTF8)) {
                    result = fail_message("the private-key label is not valid UTF-8");
                } else if (strchr(buffer, '\n') != NULL || strchr(buffer, '\r') != NULL) {
                    result = fail_message("the private-key label contains a line break");
                } else {
                    printf("%s\n", buffer);
                }
                free(buffer);
            }
            CFRelease(selected_label);
        }
        return result;
    }

    /*
     * Verification must never become another authorization prompt. The
     * partition-list command immediately before this step has already handled
     * the one intentional Keychain-password request. If resolving or reading
     * this key unexpectedly requires interaction on a future macOS release,
     * fail deterministically instead of asking again.
     */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = SecKeychainSetUserInteractionAllowed(false);
#pragma clang diagnostic pop
    if (status != errSecSuccess) {
        CFRelease(certificate);
        CFRelease(keychain);
        CFRelease(label);
        return fail_status("disable Keychain interaction during private-key verification",
                           status);
    }
    SecKeyRef key = NULL;
    status = copy_private_key_for_certificate(keychain, certificate, &key);
    CFRelease(certificate);
    if (status != errSecSuccess) {
        CFRelease(keychain);
        CFRelease(label);
        return fail_status("resolve exactly one private key from the certificate's public-key hash",
                           status);
    }

    int result = validate_key_attributes(key);
    if (result == 0) {
        result = validate_unique_resolution(keychain, key, label, false);
        if (result == 0) result = verify_acl(key);
    }
    CFRelease(key);
    CFRelease(keychain);
    CFRelease(label);
    if (result == 0) {
        printf("Signing private key %s succeeded.\n", argv[1]);
    }
    return result;
}
