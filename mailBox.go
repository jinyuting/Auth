package auth

type MailBox interface {
    SendRegisterVerification(user *User) error

    SendResetPasswordEmail(emailAddress string) error
}