package auth

import (
	"log"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

const (
	DefaultAdminUsername = "admin"
	DefaultAdminPassword = "admin123456"
)

// InitializeDefaultUser 初始化默认用户
func InitializeDefaultUser() error {
	adminUser, err := database.GetUserByUsername(DefaultAdminUsername)
	if err != nil {
		return err
	}

	hashedPassword, err := HashPassword(DefaultAdminPassword)
	if err != nil {
		return err
	}

	if adminUser == nil {
		user := database.User{
			Username:  DefaultAdminUsername,
			Password:  hashedPassword,
			Role:      "admin",
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		_, err = database.SaveUser(user)
		if err != nil {
			return err
		}

		log.Printf("已创建默认管理员账号: %s / %s", DefaultAdminUsername, DefaultAdminPassword)
	}

	return nil
}

// CreateRandomUser 创建随机用户（用于演示）
func CreateRandomUser() error {
	// 生成随机用户名
	randomUsername, err := GenerateRandomPassword(8)
	if err != nil {
		return err
	}

	// 生成随机密码
	randomPassword, err := GenerateRandomPassword(12)
	if err != nil {
		return err
	}

	// 加密密码
	hashedPassword, err := HashPassword(randomPassword)
	if err != nil {
		return err
	}

	// 创建用户
	user := database.User{
		Username:  randomUsername,
		Password:  hashedPassword,
		Role:      "user",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err = database.SaveUser(user)
	if err != nil {
		return err
	}

	log.Printf("已创建随机账号，用户名: %s，密码: %s", randomUsername, randomPassword)
	return nil
}
