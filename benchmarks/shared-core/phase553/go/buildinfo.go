package main

import "runtime/debug"

func selectedModuleVersions() map[string]string {
	selected := map[string]string{}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return selected
	}
	for _, dep := range info.Deps {
		version := dep.Version
		if dep.Replace != nil {
			version = dep.Replace.Version
			if version == "" {
				version = dep.Replace.Path
			}
		}
		selected[dep.Path] = version
	}
	return selected
}
