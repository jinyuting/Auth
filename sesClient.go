package auth

import (
    "github.com/aws/aws-sdk-go/aws/credentials"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/ses"
    "github.com/aws/aws-sdk-go/aws"
    "fmt"
    "errors"
    "log"
)

type Email struct {
    *Destination
    *Message
    Source *string
}

type Destination struct {
    BccAddresses []*string
    CcAddresses  []*string
    ToAddresses  []*string
}

type Message struct {
    Subject *Content
    Body    *Body
}
// Represents the body of the message. You can specify text, HTML, or both.
// If you use both, then the message should display correctly in the widest
// variety of email clients.
type Body struct {
    Html *Content
    Text *Content
}
// Represents textual data, plus an optional character set specification.
// By default, the text must be 7-bit ASCII, due to the constraints of the
// SMTP protocol. If the text must contain any other characters, then you must
// also specify a character set. Examples include UTF-8, ISO-8859-1, and Shift_JIS.
type Content struct {
    Charset *string
    Data    *string
}

func SendEmail(email *Email, sesClient SESClient) error {
    if email == nil || email.Destination == nil || email.Message == nil || email.Source == nil {
        return errors.New("invalidate parameter")
    }
    if len(email.Destination.ToAddresses) == 0 {
        return errors.New("no ToAddresses")
    }
    if email.Message.Body == nil || (email.Message.Body.Text == nil && email.Message.Body.Html == nil) {
        return errors.New("no body")
    }
    if email.Message.Body.Html != nil && email.Message.Body.Html.Data == nil {
        return errors.New("html body is empty")
    }
    if email.Message.Body.Text != nil && email.Message.Body.Text.Data == nil {
        return errors.New("text body is empty")
    }

    input := &ses.SendEmailInput{
        Destination: &ses.Destination{// Required
            BccAddresses: email.Destination.BccAddresses,
            CcAddresses: email.Destination.CcAddresses,
            ToAddresses: email.Destination.ToAddresses,
        },
        Message: &ses.Message{// Required
            Body: &ses.Body{// Required
                Html: &ses.Content{// Required
                    Data:    email.Body.Html.Data, // Required
                    Charset: email.Body.Html.Charset,
                },
                Text: &ses.Content{// Required
                    Data:    email.Body.Text.Data, // Required
                    Charset: email.Body.Text.Charset,
                },
            },
            Subject: &ses.Content{// Required
                Data:    email.Subject.Data, // Required
                Charset: email.Subject.Charset,
            },
        },
        Source:email.Source,
    }
    _, err := sesClient.SendEmail(input)
    if err != nil {
        log.Printf("send email failed. err=%s", err)
        return err
    }
    log.Printf("Send email successfully,email=>%v", email)
    return nil
}

type SESClient interface {
    SendEmail(input *ses.SendEmailInput) (*ses.SendEmailOutput, error)
}

func (s *Server) CreateSESClient() (SESClient, error) {
    if s.Config.SES_ACCESS_KEY == "" || s.Config.SES_SECRET_KEY == "" || s.Config.SES_REGION == "" {
        return nil, errors.New(fmt.Sprintf("missing one or more conf: %v", s.Config))
    }
    sesConfig := aws.NewConfig().WithCredentials(credentials.NewStaticCredentials(
        s.Config.SES_ACCESS_KEY, s.Config.SES_SECRET_KEY, "")).WithRegion(s.Config.SES_REGION)
    return ses.New(session.New(), sesConfig), nil
}