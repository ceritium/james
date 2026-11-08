//go:build darwin && cgo

package approve

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework AppKit -framework LocalAuthentication -framework LocalAuthenticationEmbeddedUI -framework Foundation
#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <LocalAuthenticationEmbeddedUI/LocalAuthenticationEmbeddedUI.h>

static void ui_main(void) {
	@autoreleasepool {
		[NSApplication sharedApplication];
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
		[NSApp run];
	}
}

@interface JamesDialog : NSObject <NSWindowDelegate>
@property(strong) NSWindow *window;
@property(strong) LAContext *ctx;
@property(strong) NSSegmentedControl *ttl;
@property(strong) dispatch_semaphore_t done;
@property int result;   // 1 approved, 0 denied, -2 timed out
@property long ttlIndex;
@property(copy) NSString *error;
@property BOOL finished;
@end

@implementation JamesDialog
- (void)deny:(id)sender { [self.ctx invalidate]; }
- (void)windowWillClose:(NSNotification *)n { [self.ctx invalidate]; }

// Runs on the main thread.
- (void)finish:(int)result error:(NSString *)err {
	if (self.finished) return;
	self.finished = YES;
	if (self.result != -2) self.result = result;
	self.error = err;
	self.ttlIndex = self.ttl ? self.ttl.selectedSegment : 0;
	self.window.delegate = nil;
	[self.window orderOut:nil];
	dispatch_semaphore_signal(self.done);
}
@end

static const CGFloat kWidth = 400; // content width inside the margins

static NSTextField *label(NSString *s, NSFont *font, NSColor *color, CGFloat width) {
	NSTextField *f = [NSTextField wrappingLabelWithString:s];
	f.font = font;
	f.textColor = color;
	f.selectable = YES;
	f.preferredMaxLayoutWidth = width;
	// Without a fixed width the grid lays the text out on one clipped line.
	if (width > 0) [f.widthAnchor constraintLessThanOrEqualToConstant:width].active = YES;
	return f;
}

static void fix(NSView *v, CGFloat w, CGFloat h) {
	v.translatesAutoresizingMaskIntoConstraints = NO;
	if (w > 0) [v.widthAnchor constraintEqualToConstant:w].active = YES;
	if (h > 0) [v.heightAnchor constraintEqualToConstant:h].active = YES;
}

static NSView *badge(void) {
	NSView *b = [NSView new];
	b.wantsLayer = YES;
	b.layer.cornerRadius = 11;
	b.layer.backgroundColor = NSColor.systemBlueColor.CGColor;
	fix(b, 44, 44);
	NSImageView *key = [NSImageView imageViewWithImage:
		[NSImage imageWithSystemSymbolName:@"key.fill" accessibilityDescription:nil]];
	key.symbolConfiguration = [NSImageSymbolConfiguration configurationWithPointSize:20 weight:NSFontWeightSemibold];
	key.contentTintColor = NSColor.whiteColor;
	key.translatesAutoresizingMaskIntoConstraints = NO;
	[b addSubview:key];
	[key.centerXAnchor constraintEqualToAnchor:b.centerXAnchor].active = YES;
	[key.centerYAnchor constraintEqualToAnchor:b.centerYAnchor].active = YES;
	return b;
}

static NSBox *card(NSView *content) {
	NSBox *box = [NSBox new];
	box.boxType = NSBoxCustom;
	box.cornerRadius = 10;
	box.borderWidth = 1;
	box.borderColor = NSColor.separatorColor;
	box.fillColor = [NSColor.labelColor colorWithAlphaComponent:0.04];
	box.contentViewMargins = NSMakeSize(14, 12);
	box.contentView = content;
	fix(box, kWidth, 0);
	return box;
}

static void build(JamesDialog *d, NSDictionary *p) {
	NSStackView *stack = [NSStackView stackViewWithViews:@[]];
	stack.orientation = NSUserInterfaceLayoutOrientationVertical;
	stack.alignment = NSLayoutAttributeLeading;
	stack.spacing = 16;
	stack.edgeInsets = NSEdgeInsetsMake(34, 24, 20, 24);

	NSStackView *text = [NSStackView stackViewWithViews:@[
		label(p[@"title"], [NSFont systemFontOfSize:17 weight:NSFontWeightBold], NSColor.labelColor, kWidth - 58)]];
	text.orientation = NSUserInterfaceLayoutOrientationVertical;
	text.alignment = NSLayoutAttributeLeading;
	text.spacing = 3;
	if ([p[@"subtitle"] length])
		[text addArrangedSubview:label(p[@"subtitle"], [NSFont systemFontOfSize:12], NSColor.secondaryLabelColor, kWidth - 58)];
	NSStackView *head = [NSStackView stackViewWithViews:@[badge(), text]];
	head.alignment = NSLayoutAttributeTop;
	head.spacing = 14;
	[stack addArrangedSubview:head];

	if ([p[@"quote"] length]) {
		NSFont *italic = [[NSFontManager sharedFontManager] convertFont:[NSFont systemFontOfSize:13] toHaveTrait:NSItalicFontMask];
		NSView *bar = [NSView new];
		bar.wantsLayer = YES;
		bar.layer.cornerRadius = 1.5;
		bar.layer.backgroundColor = NSColor.systemBlueColor.CGColor;
		fix(bar, 3, 0);
		NSStackView *q = [NSStackView stackViewWithViews:@[bar,
			label([NSString stringWithFormat:@"“%@”", p[@"quote"]], italic, NSColor.labelColor, kWidth - 16)]];
		q.alignment = NSLayoutAttributeTop;
		q.spacing = 10;
		[bar.heightAnchor constraintEqualToAnchor:q.heightAnchor].active = YES;
		[stack addArrangedSubview:q];
	}

	NSGridView *grid = [NSGridView gridViewWithViews:@[]];
	grid.rowSpacing = 9;
	grid.columnSpacing = 14;
	for (NSDictionary *r in p[@"rows"]) {
		NSTextField *k = label(r[@"label"], [NSFont systemFontOfSize:11 weight:NSFontWeightMedium], NSColor.secondaryLabelColor, 0);
		NSFont *vf = [r[@"mono"] boolValue]
			? [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular]
			: [NSFont systemFontOfSize:12];
		NSTextField *v = label(r[@"value"], vf, NSColor.labelColor, kWidth - 110);
		if ([r[@"mono"] boolValue]) v.lineBreakMode = NSLineBreakByCharWrapping;
		[grid addRowWithViews:@[k, v]];
	}
	if (grid.numberOfRows > 0) {
		for (NSInteger i = 0; i < grid.numberOfRows; i++) [grid rowAtIndex:i].rowAlignment = NSGridRowAlignmentFirstBaseline;
		[stack addArrangedSubview:card(grid)];
	}

	NSArray *ttls = p[@"ttls"];
	if (ttls.count > 0) {
		NSSegmentedControl *seg = [NSSegmentedControl segmentedControlWithLabels:ttls
			trackingMode:NSSegmentSwitchTrackingSelectOne target:nil action:nil];
		seg.selectedSegment = [p[@"ttl_index"] integerValue];
		seg.segmentDistribution = NSSegmentDistributionFillEqually;
		fix(seg, MIN(70 * ttls.count, kWidth - 80), 0);
		d.ttl = seg;
		NSStackView *row = [NSStackView stackViewWithViews:@[
			label(@"Allow for", [NSFont systemFontOfSize:13], NSColor.secondaryLabelColor, 0), seg]];
		row.spacing = 12;
		[stack addArrangedSubview:row];
	}

	NSBox *line = [NSBox new];
	line.boxType = NSBoxSeparator;
	fix(line, kWidth, 0);
	[stack addArrangedSubview:line];

	LAAuthenticationView *auth = [[LAAuthenticationView alloc] initWithContext:d.ctx controlSize:NSControlSizeSmall];
	fix(auth, 34, 34);
	NSView *spacer = [NSView new];
	[spacer setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
	NSButton *deny = [NSButton buttonWithTitle:@"Deny" target:d action:@selector(deny:)];
	deny.keyEquivalent = @"\e";
	deny.controlSize = NSControlSizeLarge;
	NSStackView *foot = [NSStackView stackViewWithViews:@[auth,
		label(@"Touch ID to approve", [NSFont systemFontOfSize:13 weight:NSFontWeightMedium], NSColor.labelColor, 0), spacer, deny]];
	foot.spacing = 10;
	fix(foot, kWidth, 0);
	[stack addArrangedSubview:foot];

	NSVisualEffectView *bg = [NSVisualEffectView new];
	bg.material = NSVisualEffectMaterialWindowBackground;
	bg.blendingMode = NSVisualEffectBlendingModeBehindWindow;
	bg.state = NSVisualEffectStateActive;
	stack.translatesAutoresizingMaskIntoConstraints = NO;
	[bg addSubview:stack];
	[NSLayoutConstraint activateConstraints:@[
		[stack.topAnchor constraintEqualToAnchor:bg.topAnchor],
		[stack.bottomAnchor constraintEqualToAnchor:bg.bottomAnchor],
		[stack.leadingAnchor constraintEqualToAnchor:bg.leadingAnchor],
		[stack.trailingAnchor constraintEqualToAnchor:bg.trailingAnchor],
	]];

	NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, kWidth + 48, 300)
		styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskFullSizeContentView
		backing:NSBackingStoreBuffered defer:NO];
	w.title = @"james";
	w.titleVisibility = NSWindowTitleHidden;
	w.titlebarAppearsTransparent = YES;
	w.movableByWindowBackground = YES;
	[w standardWindowButton:NSWindowMiniaturizeButton].hidden = YES;
	[w standardWindowButton:NSWindowZoomButton].hidden = YES;
	w.releasedWhenClosed = NO;
	w.level = NSModalPanelWindowLevel;
	w.contentView = bg;
	w.delegate = d;
	d.window = w;
	[w layoutIfNeeded];
	[w setContentSize:stack.fittingSize];
	[w center];
	[NSApp activateIgnoringOtherApps:YES];
	[w makeKeyAndOrderFront:nil];
}

// Returns 1 approved, 0 denied, -1 no biometrics, -2 timed out.
static int ui_ask(const char *json, const char *reason, int timeout, long *ttlIndex, char *errbuf, int errcap) {
	@autoreleasepool {
		NSData *data = [NSData dataWithBytes:json length:strlen(json)];
		NSDictionary *p = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
		JamesDialog *d = [JamesDialog new];
		d.done = dispatch_semaphore_create(0);
		d.ctx = [LAContext new];
		d.ctx.localizedFallbackTitle = @"";
		NSError *err = nil;
		if (!p || ![d.ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&err]) {
			snprintf(errbuf, errcap, "%s", err ? err.localizedDescription.UTF8String : "bad prompt");
			return -1;
		}
		NSString *why = [NSString stringWithUTF8String:reason];
		dispatch_async(dispatch_get_main_queue(), ^{
			build(d, p);
			[d.ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:why
			                reply:^(BOOL ok, NSError *e) {
				dispatch_async(dispatch_get_main_queue(), ^{
					[d finish:ok ? 1 : 0 error:ok ? nil : [NSString stringWithFormat:@"%@ (LAError %ld)", e.localizedDescription, (long)e.code]];
				});
			}];
		});
		if (dispatch_semaphore_wait(d.done, dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout * NSEC_PER_SEC)) != 0) {
			dispatch_async(dispatch_get_main_queue(), ^{
				if (d.finished) return;
				d.result = -2;
				[d.ctx invalidate];
				[d finish:-2 error:@"timed out"];
			});
			dispatch_semaphore_wait(d.done, DISPATCH_TIME_FOREVER);
		}
		*ttlIndex = d.ttlIndex;
		if (d.error) snprintf(errbuf, errcap, "%s", d.error.UTF8String);
		return d.result;
	}
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"time"
	"unsafe"
)

const dialogTimeout = 2 * time.Minute

// Main runs the AppKit event loop and never returns. It must run on the main
// thread: call it from the main goroutine with runtime.LockOSThread in init.
func Main() { C.ui_main() }

// Ask shows p in a james window with an embedded Touch ID sensor and returns
// the duration the user picked. Without a Touch ID sensor it falls back to the
// system sheet, which also accepts an Apple Watch.
func Ask(p Prompt) (time.Duration, error) {
	mu.Lock()
	defer mu.Unlock()

	ui := struct {
		Prompt
		TTLs     []string `json:"ttls"`
		TTLIndex int      `json:"ttl_index"`
	}{Prompt: p}
	for i, d := range p.TTLs {
		ui.TTLs = append(ui.TTLs, FormatDuration(d))
		if d == p.TTL {
			ui.TTLIndex = i
		}
	}
	js, err := json.Marshal(ui)
	if err != nil {
		return 0, err
	}
	cJSON := C.CString(string(js))
	defer C.free(unsafe.Pointer(cJSON))
	cReason := C.CString(p.Title)
	defer C.free(unsafe.Pointer(cReason))

	var idx C.long
	buf := make([]byte, 256)
	r := C.ui_ask(cJSON, cReason, C.int(dialogTimeout/time.Second), &idx, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	msg := C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
	switch r {
	case 1:
		if i := int(idx); i >= 0 && i < len(p.TTLs) {
			return p.TTLs[i], nil
		}
		return p.TTL, nil
	case -1:
		return p.TTL, touchid(p.Text)
	case -2:
		return 0, fmt.Errorf("%w: no answer within %s", ErrDenied, dialogTimeout)
	}
	if msg != "" {
		return 0, fmt.Errorf("%w: %s", ErrDenied, msg)
	}
	return 0, ErrDenied
}
