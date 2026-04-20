package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// GenerateRandomPassword 生成随机密码
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

	password := make([]byte, length)
	for i := range password {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[num.Int64()]
	}

	return string(password), nil
}

// HashPassword 使用bcrypt加密密码
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedPassword), nil
}

// VerifyPassword 验证密码
func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateToken 生成简单的JWT token（简化版）
func GenerateToken(username string) (string, error) {
	// 创建payload
	payload := fmt.Sprintf(`{"username":"%s","exp":%d}`, username, time.Now().Add(24*time.Hour).Unix())

	// 简单的签名（实际项目中应使用更安全的签名方式）
	signature := sha256.Sum256([]byte(payload + "trailblazer_secret_key"))

	// Base64编码
	encodedPayload := base64.URLEncoding.EncodeToString([]byte(payload))
	encodedSignature := base64.URLEncoding.EncodeToString(signature[:])

	return fmt.Sprintf("%s.%s", encodedPayload, encodedSignature), nil
}

// ValidateToken 验证token
func ValidateToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid token format")
	}

	// 解码payload
	payloadBytes, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid token payload")
	}

	// 验证签名
	expectedSignature := sha256.Sum256([]byte(string(payloadBytes) + "trailblazer_secret_key"))
	actualSignature, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid token signature")
	}

	if !bytesEqual(expectedSignature[:], actualSignature) {
		return "", fmt.Errorf("invalid token signature")
	}

	// 解析payload获取用户名
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("invalid token payload")
	}

	// 检查过期时间
	if exp, ok := payload["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return "", fmt.Errorf("token expired")
		}
	}

	username, ok := payload["username"].(string)
	if !ok {
		return "", fmt.Errorf("invalid username in token")
	}

	return username, nil
}

// bytesEqual 比较两个字节数组是否相等
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
