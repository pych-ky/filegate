package vmbridge

func ReadProductRequest(path, expected string) (map[string]any, error) {
	return request(path, expected)
}

func ValidateProductProgress(value map[string]any) error {
	_, err := progress(value)
	return err
}

func ValidateProductReport(value, requested map[string]any) error {
	return report(value, requested)
}

func DecodeObject(body []byte) (map[string]any, error) {
	value, err := decode(body)
	result, ok := value.(object)
	if err != nil || !ok {
		return nil, errInvalid
	}
	return result, nil
}

func ValidateFixturePreflight(value map[string]any) bool {
	return preflight(value, object{})
}

func NormalizeWorkspace(value map[string]any) (map[string]any, error) {
	return workspace(value)
}
