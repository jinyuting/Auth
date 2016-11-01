package auth

import (
    "errors"
    "time"
    "net/mail"
    log "github.com/cihub/seelog"
)

func (s *Server) SendResetPasswordEmail(emailAddress string, template *EmailTemplate) error {
    e, err := mail.ParseAddress(emailAddress)
    if err != nil {
        log.Error(err)
        return err
    }
    user, err := s.Storage.GetUserByEmail(e.Address)
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
    return SendEmail(token, user.Email, template, client)
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
    //if user.Status != USER_STATUS_NORMAL {
    //    return errors.New("User status is not normal, cannot change password")
    //}
    user.Password = password
    if err = s.Storage.UpdateUser(user); err == nil {
        err = s.Storage.ExpireToken(token)
    }
    return err
}