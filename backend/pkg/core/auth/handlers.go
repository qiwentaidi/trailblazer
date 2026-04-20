package auth

import (
	"log"
	"net/http"

	"trailblazer/pkg/core/database"

	"github.com/gin-gonic/gin"
)

// LoginHandler 登录处理器
func LoginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
		return
	}

	// 获取用户
	user, err := database.GetUserByUsername(req.Username)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Internal server error",
		})
		return
	}

	if user == nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error: "Invalid username or password",
		})
		return
	}

	// 验证密码
	if err := VerifyPassword(user.Password, req.Password); err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error: "Invalid username or password",
		})
		return
	}

	// 生成token
	token, err := GenerateToken(user.Username)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token:    token,
		Username: user.Username,
		Role:     user.Role,
		Message:  "Login successful",
	})
}

// GetUserInfoHandler 获取用户信息处理器
func GetUserInfoHandler(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	user, err := database.GetUserByUsername(username.(string))
	if err != nil {
		log.Printf("Error getting user info: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Internal server error",
		})
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, UserInfo{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.Role,
		IsActive: user.IsActive,
	})
}

// LogoutHandler 登出处理器
func LogoutHandler(c *gin.Context) {
	// 由于使用无状态token，登出只需要客户端删除token
	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}
