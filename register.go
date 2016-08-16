package auth

import (
    "net/mail"
    "log"
    "github.com/go-errors/errors"
    "sproject/infra/timeUtil"
    "github.com/astaxie/beego"
    "sproject/infra/notification"
    "sproject/infra/typeUtil"
    "fmt"
)

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
    return s.MailBox.SendRegisterVerification(user)
}

func SendVerificationEmail(email string) error {
    user, err := cbGetUserByEmail(email)
    if err != nil {
        return err
    }
    b, err := json.Marshal(&EmailVerification{
        Email:      email,
        CreateTime: timeUtil.CurrentTime(),
    })
    token, err := cbNewToken(models.TOKEN_TYPE_VERIFY_EMAIL, timeUtil.HOUR, user.Id, string(b))
    if err != nil {
        return errors.New("failed to generate a new token")
    }
    verifyUrl := beego.AppConfig.String("email_verification_path") + token
    body := `<html>
        <body>
            <b>Please click the following link to verify your email:</b>
            <br>
            <a href="%s">%s</a>
        </body>
    </html>`

    verifyEmail := &notification.Email{
        Destination: &notification.Destination{ToAddresses:[]*string{&email}},
        Message: &notification.Message{
            Subject:&notification.Content{
                Charset:typeUtil.String("UTF-8"),
                Data:typeUtil.String("Anker User Email Verification"),
            },
            Body:&notification.Body{
                Html: &notification.Content{
                    Charset:typeUtil.String("UTF-8"),
                    Data:typeUtil.String(fmt.Sprintf(body, verifyUrl, verifyUrl)),
                },
                Text: &notification.Content{
                    Charset:typeUtil.String("UTF-8"),
                    Data:typeUtil.String(token),
                },
            },
        },
        Source: typeUtil.String(EMAIL_DEFAULT_SOURCE),
    }
    return cbSendEmail(verifyEmail)
}
