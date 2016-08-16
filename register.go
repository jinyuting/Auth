package auth

import (
    "net/mail"
    "log"
    "github.com/go-errors/errors"
    "sproject/infra/timeUtil"
    "sproject/infra/typeUtil"
    "fmt"
    "time"
)

const DEFAULT_CHAR_SET = "UTF-8"

type EmailRegisterRequest struct {
    OpenUDID string `json:"open_udid"`
    Email    string `json:"email"`
    Password string `json:"password"`
    Name     string `json:"name"`
}

func (s *Server) CheckEmailRegistered(email string) error {
    user, err := s.Storage.GetUserByEmail(email)
    if err != nil {
        return err
    }
    if user != nil {
        return errors.New("The Email is already registered")
    }
    return nil
}

func (s *Server) RegisterByEmail(req *EmailRegisterRequest) error {
    if len(req.Email) == 0 || len(req.Password) == 0 {
        return errors.New("invalid email or password")
    }
    e, err := mail.ParseAddress(req.Email)
    if err != nil {
        log.Print(err)
        return err
    }
    if err = s.CheckEmailRegistered(e.Address); err != nil {
        return err
    }
    user, err := s.Storage.CreateUser(&User{Email:e.Address, Password:req.Password, Name:req.Name})
    if err != nil {
        return err
    }
    return s.SendVerificationEmail(user.Email)
}

func (s *Server) SendVerificationEmail(email string) error {
    user, err := s.Storage.GetUserByEmail(email)
    if err != nil {
        return err
    }

    token, err := s.Storage.NewToken(TOKEN_TYPE_VERIFY_EMAIL, timeUtil.HOUR, user.Id)
    if err != nil || len(token) == 0 {
        return errors.New("failed to generate a new token")
    }
    template := s.Config.VerificationEmailTemplate
    verifyEmail := &Email{
        Destination: &Destination{ToAddresses:[]*string{&user.Email}},
        Message: &Message{
            Subject:&Content{
                Charset:typeUtil.String(DEFAULT_CHAR_SET),
                Data:typeUtil.String(template.Subject),
            },
            Body:&Body{
                Html: &Content{
                    Charset:typeUtil.String(DEFAULT_CHAR_SET),
                    Data:typeUtil.String(fmt.Sprintf(template.Body, token, token)),
                },
                // Ignore the text part
                Text: &Content{
                    Charset:typeUtil.String(DEFAULT_CHAR_SET),
                    Data:typeUtil.String(""),
                },
            },
        },
        Source: typeUtil.String(template.Source),
    }
    client, err := s.CreateSESClient()
    if err != nil {
        return err
    }
    return SendEmail(verifyEmail, client)
}

func (s *Server) VerifyEmailAddress(token string) error {
    tokenObject, err := s.Storage.GetToken(token)
    // Each token can only be used once
    defer s.Storage.ExpireToken(token)
    if err != nil || tokenObject == nil {
        return errors.New("Invalid token")
    }
    if tokenObject.Type != TOKEN_TYPE_VERIFY_EMAIL {
        return errors.New("token type is invalid")
    }
    if tokenObject.ExpiredAt <= time.Now().Unix() {
        return errors.New("The token is expired.")
    }
    // check user
    user, err := s.Storage.GetUser(tokenObject.UserId)
    if err != nil {
        return err
    }
    if user == nil {
        return errors.New("User not exists!")
    }
    user.Status = USER_STATUS_NORMAL
    return s.Storage.UpdateUser(user)
}
