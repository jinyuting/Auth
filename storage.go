package auth

type User struct {
    Id       string
    Email    string
    Name     string
    Password string
    Status   UserStatus
}

type Token struct {
    Code      string
    UserId    string
    Type      TokenType
    ExpiredAt int64
}

type TokenType int

const (
    TOKEN_TYPE_SANDBOX_TEST TokenType = iota
    TOKEN_TYPE_VERIFY_EMAIL
    TOKEN_TYPE_RESET_PASSWORD
)

type Storage interface {
    //
    CreateUser(user *User) (*User, error)

    UpdateUser(user *User) error

    GetUser(userId string) (*User, error)

    GetUserByEmail(email string) (*User, error)

    BindUserToOpenUDID(userId, openUDID string) error

    UnBindUserToOpenUDID(userId, openUDID string) error

    NewToken(tokenType TokenType, interval int64, userId string) (string, error)

    GetToken(code string) (*Token, error)

    ExpireToken(code string) error
}