package auth

import (
    "errors"
    "time"
)

func (s *Server) SendResetPasswordEmail(emailAddress string) error {
    user, err := s.Storage.GetUserByEmail(emailAddress)
    if err != nil {
        return err
    }
    if user == nil {
        return errors.New("User with this email does not exist!")
    }
    token, err := s.Storage.NewToken(TOKEN_TYPE_RESET_PASSWORD, s.Config.TokenExpire, user.Id)
    if err != nil {
        return errors.New("failed to generate a new token")
    }
    client, err := s.CreateSESClient()
    if err != nil {
        return err
    }
    return SendEmail(user.Email, token, s.Config.ResetPasswordEmailTemplate, client)
}

func (s *Server) ResetPassword(token, password string) error {
    tokenObj, err := s.Storage.GetToken(token)
    if err != nil {
        return err
    }
    if tokenObj == nil || tokenObj.Type != TOKEN_TYPE_RESET_PASSWORD {
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
    user.Password = password
    return s.Storage.UpdateUser(user)
}