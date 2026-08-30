//go:build linux

package context

import "github.com/MoSLoF/scrutiny2.0/internal/schema"

// detectWindows is never called on Linux. Stub satisfies the compiler
// when detect.go (shared) references it via the runtime.GOOS check.
func detectWindows() (schema.PlatformContext, error) {
	return schema.PlatformContext{DetectedPlatform: schema.ContextUnknown}, nil
}
