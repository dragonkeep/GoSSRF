package scanner

import (
	"fmt"
	"net/url"
	"strings"
)

// buildTestURL 构造测试URL（GET方式）
func buildTestURL(baseURL string, paramName string, payload string) (string, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	q := parsedURL.Query()
	q.Set(paramName, payload)
	parsedURL.RawQuery = q.Encode()

	return parsedURL.String(), nil
}

// buildTestBody 构造测试Body（POST方式）
func buildTestBody(paramName string, payload string) string {
	// 构造 application/x-www-form-urlencoded 格式
	values := url.Values{}
	values.Set(paramName, payload)
	return values.Encode()
}

// buildTestRequest 构造测试请求数据
func buildTestRequest(method, baseURL, paramName, payload string) (string, string, error) {
	method = strings.ToUpper(method)

	switch method {
	case "GET":
		testURL, err := buildTestURL(baseURL, paramName, payload)
		return testURL, "", err
	case "POST", "PUT", "PATCH":
		body := buildTestBody(paramName, payload)
		return baseURL, body, nil
	default:
		return "", "", fmt.Errorf("不支持的HTTP方法: %s", method)
	}
}
