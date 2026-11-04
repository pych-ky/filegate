package av

import (
	"context"
	"sort"
)

func FixtureProfile() map[string]any {
	values := make(map[string]string, len(settings))
	for name, value := range settings {
		values[name] = value
	}
	return map[string]any{"profile_id": ProfileID, "settings": values, "settings_sha256": ConfigurationSHA256,
		"enabled": false, "av_coverage_assurance": "standard_engine_best_effort"}
}

func FixtureArguments(overrides map[string]string) ([]string, error) {
	values := make(map[string]string, len(settings))
	for name, value := range settings {
		values[name] = value
	}
	for name, value := range overrides {
		if _, ok := values[name]; !ok {
			return nil, invalid
		}
		values[name] = value
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	arguments := make([]string, 0, len(names))
	for _, name := range names {
		arguments = append(arguments, "--"+name+"="+values[name])
	}
	return arguments, nil
}

func FixtureRuntime(ctx context.Context) (Profile, *Binding, error) {
	profile, binding, err := loadProfile()
	if err == nil && !profile.FixtureDefinitionsOnly {
		err = invalid
	}
	if err == nil {
		err = verifyRuntime(ctx, profile, binding)
	}
	return profile, binding, err
}
