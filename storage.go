package auth

type User struct {
    Id       string
    Email    string
    Name     string
    Password string
    Status   UserStatus
}

type Storage interface {
    //
    CreateUser(user *User) (*User, error)

    GetUser(userId string) (*User, error)

    GetUserByEmail(email string) (*User, error)

    BindUserToOpenUDID(userId, openUDID string) error

    UnBindUserToOpenUDID(userId, openUDID string) error
}