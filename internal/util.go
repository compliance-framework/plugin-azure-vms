package internal

import (
	"errors"
	"strings"
)

func MergeMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, imap := range maps {
		for k, v := range imap {
			result[k] = v
		}
	}
	return result
}

func StringAddressed(str string) *string {
	return &str
}

// ParseAzureResourceID parses an Azure resource ID into its components.
func ParseAzureResourceID(resourceID string) (map[string]string, error) {
	if resourceID == "" {
		return nil, errors.New("resourceID cannot be empty")
	}

	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	if len(parts)%2 != 0 {
		return nil, errors.New("invalid Azure resource ID format")
	}

	result := make(map[string]string)
	for i := 0; i < len(parts)-1; i += 2 {
		result[parts[i]] = parts[i+1]
	}
	return result, nil
}
