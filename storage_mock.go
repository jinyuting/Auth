package auth

import "time"

type MockStorage struct {
    //
}

func (MockStorage) CreateUser(user *User) (*User, error) {
    return &User{Id:"mock userId", Email:"yuting.jin@oceanwing.com", Password:"123"}, nil
}

func (MockStorage) UpdateUser(user *User) error {
    return nil
}

func (MockStorage) GetUser(userId string) (*User, error) {
    return &User{Id:"mock userId", Email:"yuting.jin@oceanwing.com", Password:"123"}, nil
}

func (MockStorage) GetUserByEmail(email string) (*User, error) {
    return &User{Id:"mock userId", Email:"yuting.jin@oceanwing.com", Password:"123"}, nil
}

func (MockStorage) BindUserToOpenUDID(userId, openUDID string) error {
    return nil
}

func (MockStorage) UnBindUserToOpenUDID(userId, openUDID string) error {
    return nil
}

func (MockStorage) NewToken(tokenType TokenType, interval int64, userId string) (string, error) {
    return "mockToken", nil
}

func (MockStorage) GetToken(code string) (*Token, error) {
    return &Token{
        Code:      "mockToken",
        UserId:    "mock userId",
        Type:      TOKEN_TYPE_SANDBOX_TEST,
        ExpiredAt: time.Now().Unix() + 10000,
    }, nil
}

func (MockStorage) ExpireToken(code string) error {
    return nil
}