//go:build windows

package pack

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x00000001
	moveFileWriteThrough    = 0x00000008
)

var (
	kernel32MoveFile = syscall.NewLazyDLL("kernel32.dll")
	moveFileExW      = kernel32MoveFile.NewProc("MoveFileExW")
)

func atomicReplaceDurable(temp, target string) (bool, error) {
	from, err := syscall.UTF16PtrFromString(temp)
	if err != nil {
		return false, err
	}
	to, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return false, err
	}
	result, _, callErr := moveFileExW.Call(
		uintptr(unsafe.Pointer(from)),
		uintptr(unsafe.Pointer(to)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return false, callErr
		}
		return false, fmt.Errorf("MoveFileExW failed without Win32 error")
	}
	return true, nil
}
