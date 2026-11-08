//go:build darwin && cgo

// Package approve asks the user to confirm a request with Touch ID.
package approve

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>

// Returns 1 approved, 0 denied or cancelled, <0 unavailable. Biometrics or a
// companion device (Apple Watch) only: a password fallback could be typed by a same-user
// process with Accessibility access.
static int touchid(const char *reason, char *errbuf, int errcap) {
	@autoreleasepool {
		LAContext *ctx = [[LAContext alloc] init];
		ctx.localizedFallbackTitle = @"";
		LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
		if (@available(macOS 15.0, *)) policy = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion;
		NSError *err = nil;
		if (![ctx canEvaluatePolicy:policy error:&err]) {
			snprintf(errbuf, errcap, "%s", err.localizedDescription.UTF8String);
			return -1;
		}
		__block int result = 0;
		__block NSString *msg = nil;
		dispatch_semaphore_t done = dispatch_semaphore_create(0);
		[ctx evaluatePolicy:policy
		    localizedReason:[NSString stringWithUTF8String:reason]
		              reply:^(BOOL ok, NSError *e) {
			result = ok ? 1 : 0;
			if (!ok && e) msg = e.localizedDescription;
			dispatch_semaphore_signal(done);
		}];
		dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
		if (msg) snprintf(errbuf, errcap, "%s", msg.UTF8String);
		return result;
	}
}
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

var (
	ErrDenied      = errors.New("request denied")
	ErrUnavailable = errors.New("Touch ID unavailable")
)

// One prompt at a time; LocalAuthentication would otherwise stack them.
var mu sync.Mutex

// TouchID shows reason in the system Touch ID dialog and blocks until the user answers.
func TouchID(reason string) error {
	mu.Lock()
	defer mu.Unlock()
	return touchid(reason)
}

func touchid(reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	buf := make([]byte, 256)
	r := C.touchid(cReason, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	msg := C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
	switch {
	case r == 1:
		return nil
	case r < 0:
		return fmt.Errorf("%w: %s", ErrUnavailable, msg)
	case msg != "":
		return fmt.Errorf("%w: %s", ErrDenied, msg)
	default:
		return ErrDenied
	}
}
