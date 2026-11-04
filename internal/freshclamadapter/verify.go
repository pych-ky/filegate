package freshclamadapter

func VerifyLibrary(path string) (string, error) {
	library, sum, err := loadRuntime(path)
	if err != nil {
		return "", err
	}
	library.close()
	return sum, nil
}
