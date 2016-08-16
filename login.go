package auth

import (
    "log"
    "errors"
)

type UserStatus int

const (
    USER_STATUS_NOT_VERIFY UserStatus = 0
    USER_STATUS_NORMAL UserStatus = 1
    USER_STATUS_LOCKED UserStatus = 2
    USER_STATUS_DELETED UserStatus = 3
)

type LoginRequest struct {
    OpenUDID string `json:"open_udid"`
    UserId   string `json:"user_id"`
    Email    string `json:"email"`
    Password string `json:"password"`
    Token    string `json:"token"`
}

type LoginResponse struct {
    UserId string `json:"user_id"`
    Email  string `json:"email"`
}

func (s *Server) EmailLogin(req *LoginRequest) (*LoginResponse, error) {
    if req == nil || req.Email == "" || req.Password == "" {
        return nil, errors.New("Invalid email login request")
    }
    user, err := s.Storage.GetUserByEmail(req.Email)
    if err != nil {
        log.Print(err)
        return nil, err
    }
    if user == nil || user.Status == USER_STATUS_DELETED || user.Password != req.Password {
        return nil, errors.New("Invalid user or password")
    }
    if user.Status == USER_STATUS_NOT_VERIFY {
        return nil, errors.New("The user is not verified")
    }
    if user.Status == USER_STATUS_LOCKED {
        return nil, errors.New("The user is locked")
    }
    if err = s.Storage.BindUserToOpenUDID(user.Id, req.OpenUDID); err != nil {
        log.Printf("bind userId to openUDID failed. userId=%s, openUDID=%s, err= %s", user.Id, req.OpenUDID, err)
        return nil, err
    }

    return &LoginResponse{UserId:user.Id, Email:user.Email}, nil
}

type LogoutRequest struct {
    UserId   string `json:"user_id"`
    OpenUDID string `json:"open_udid"`
}

func (s *Server) Logout(req *LogoutRequest) error {
    // TODO anything else?
    return s.Storage.UnBindUserToOpenUDID(req.UserId, req.OpenUDID)
}