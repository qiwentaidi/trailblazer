package auth

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"

	"github.com/gin-gonic/gin"
)

func validateUsernameAndPassword(username, password string) string {
	if strings.TrimSpace(username) == "" {
		return "用户名不能为空"
	}
	if len([]rune(strings.TrimSpace(username))) < 3 {
		return "用户名至少需要 3 个字符"
	}
	if len(password) < 8 {
		return "密码至少需要 8 个字符"
	}
	return ""
}

// GetAuthStatusHandler 获取账号初始化状态
func GetAuthStatusHandler(c *gin.Context) {
	count, err := database.CountUsers()
	if err != nil {
		log.Printf("统计用户数量失败: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, AuthStatusResponse{
		Initialized: count > 0,
	})
}

// InitializeAccountHandler 初始化首个管理员账号
func InitializeAccountHandler(c *gin.Context) {
	var req InitAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
		return
	}

	if msg := validateUsernameAndPassword(req.Username, req.Password); msg != "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: msg})
		return
	}

	count, err := database.CountUsers()
	if err != nil {
		log.Printf("统计用户数量失败: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Internal server error",
		})
		return
	}
	if count > 0 {
		c.JSON(http.StatusConflict, ErrorResponse{
			Error: "Account already initialized",
		})
		return
	}

	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		log.Printf("生成初始密码哈希失败: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to initialize account",
		})
		return
	}

	_, err = database.SaveUser(database.User{
		Username:  strings.TrimSpace(req.Username),
		Password:  hashedPassword,
		Role:      "admin",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		log.Printf("保存初始用户失败: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to initialize account",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Account initialized successfully",
	})
}

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
		log.Printf("获取用户失败: %v", err)
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
		log.Printf("生成令牌失败: %v", err)
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
		log.Printf("获取用户信息失败: %v", err)
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

// ChangePasswordHandler 修改当前用户密码
func ChangePasswordHandler(c *gin.Context) {
	usernameValue, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
		return
	}

	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "密码至少需要 8 个字符",
		})
		return
	}

	username := usernameValue.(string)
	user, err := database.GetUserByUsername(username)
	if err != nil {
		log.Printf("获取待修改密码的用户失败: %v", err)
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

	if err := VerifyPassword(user.Password, req.OldPassword); err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error: "旧密码错误",
		})
		return
	}

	hashedPassword, err := HashPassword(req.NewPassword)
	if err != nil {
		log.Printf("生成新密码哈希失败: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to update password",
		})
		return
	}

	if err := database.UpdateUserPasswordByUsername(username, hashedPassword); err != nil {
		log.Printf("更新密码失败: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to update password",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password updated successfully",
	})
}
