package auth

import (
    "log"
    "errors"
    "time"
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
}

type LoginResponse struct {
    UserId string `json:"user_id"`
    Email  string `json:"email"`
    Name   string `json:"name"`
}

func (s *Server) Login(req *LoginRequest) (*LoginResponse, error) {
    if req == nil || req.UserId == "" || req.Password == "" {
        return nil, errors.New("Invalid id and password login request")
    }
    user, err := s.Storage.GetUser(req.UserId)
    if err != nil {
        log.Print(err)
        return nil, err
    }
    if user == nil || user.Status == USER_STATUS_DELETED || user.Password != req.Password {
        return nil, errors.New("Invalid user or password")
    }
    if user.Status == USER_STATUS_LOCKED {
        return nil, errors.New("The user is locked")
    }
    if err = s.Storage.BindUserToOpenUDID(user.Id, req.OpenUDID); err != nil {
        log.Printf("bind userId to openUDID failed. userId=%s, openUDID=%s, err= %s", user.Id, req.OpenUDID, err)
        return nil, err
    }

    return &LoginResponse{UserId:user.Id, Email:user.Email, Name: user.Name}, nil
}

func (s *Server) EmailLogin(req *LoginRequest) (*LoginResponse, error) {
    if req == nil || req.Email == "" || req.Password == "" {
        return nil, errors.New("Invalid email and password login request")
    }
    user, err := s.Storage.GetUserByEmail(req.Email)
    if err != nil {
        log.Print(err)
        return nil, err
    }
    if user == nil || user.Status == USER_STATUS_DELETED || user.Password != req.Password {
        return nil, errors.New("Invalid user or password")
    }
    if user.Status == USER_STATUS_LOCKED {
        return nil, errors.New("The user is locked")
    }
    if err = s.Storage.BindUserToOpenUDID(user.Id, req.OpenUDID); err != nil {
        log.Printf("bind userId to openUDID failed. userId=%s, openUDID=%s, err= %s", user.Id, req.OpenUDID, err)
        return nil, err
    }

    return &LoginResponse{UserId:user.Id, Email:user.Email, Name: user.Name}, nil
}

type LogoutRequest struct {
    UserId   string `json:"user_id"`
    OpenUDID string `json:"open_udid"`
}

func (s *Server) Logout(req *LogoutRequest) error {
    if req == nil || len(req.OpenUDID) == 0 || len(req.UserId) == 0 {
        return errors.New("Invalid logout request")
    }
    return s.Storage.UnBindUserToOpenUDID(req.UserId, req.OpenUDID)
}

func (s *Server) VerifyToken(token string, tokenType TokenType) error {
    tokenObj, err := s.Storage.GetToken(token)
    if err != nil {
        return err
    }
    if tokenObj == nil || tokenObj.Type != tokenType {
        return errors.New("Invalid token")
    }
    if tokenObj.ExpiredAt < time.Now().Unix() {
        return errors.New("Expired token")
    }
    // check user
    user, err := s.Storage.GetUser(tokenObj.UserId)
    if err != nil {
        return err
    }
    if user == nil {
        return errors.New("User not exists!")
    }
    if user.Status != USER_STATUS_NORMAL {
        return errors.New("User status is not normal, cannot change passowrd")
    }
    return nil
}