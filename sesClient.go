package auth

import (
    "github.com/aws/aws-sdk-go/aws/credentials"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/ses"
    "github.com/aws/aws-sdk-go/aws"
    "fmt"
    "errors"
    "bytes"
    "strings"
    "html/template"
    log "github.com/cihub/seelog"
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

func SendEmail(token, emailAddress string, template *EmailTemplate, client SESClient) error {
    body, err := ParseHtmlMsgContent(template.Body, struct{ Token string }{Token: token})
    if err != nil {
        log.Errorf("Parse email body failed. err=%s", err)
    }

    email := &Email{
        Destination: &Destination{ToAddresses:[]*string{&emailAddress}},
        Message: &Message{
            Subject:&Content{
                Charset:String(DEFAULT_CHAR_SET),
                Data:String(template.Subject),
            },
            Body:&Body{
                Html: &Content{
                    Charset:String(DEFAULT_CHAR_SET),
                    Data:String(body),
                },
                // Ignore the text part
                Text: &Content{
                    Charset:String(DEFAULT_CHAR_SET),
                    Data:String(""),
                },
            },
        },
        Source: String(template.Source),
    }
    return doSendEmail(email, client)
}

func ParseHtmlMsgContent(msg string, values interface{}) (string, error) {
    msgTemp := template.Must(template.New("template id").Parse(msg))
    out := bytes.NewBuffer(nil)
    //将string与模板合成，变量token的内容会替换掉{{.token}}
    if err := msgTemp.Execute(out, values); err != nil {
        return "", err
    }
    return strings.TrimSpace(out.String()), nil
}

func doSendEmail(email *Email, sesClient SESClient) error {
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
        log.Errorf("send email failed. err=%s", err)
        return err
    }
    log.Debugf("Send email successfully,email=>%v", email)
    return nil
}

type SESClient interface {
    SendEmail(input *ses.SendEmailInput) (*ses.SendEmailOutput, error)
}

func (s *Server) CreateSESClient() (SESClient, error) {
    config := s.Config.SesConfig
    if config.SES_ACCESS_KEY == "" || config.SES_SECRET_KEY == "" || config.SES_REGION == "" {
        return nil, errors.New(fmt.Sprintf("missing one or more conf: %v", config))
    }
    sesConfig := aws.NewConfig().WithCredentials(credentials.NewStaticCredentials(
        config.SES_ACCESS_KEY, config.SES_SECRET_KEY, "")).WithRegion(config.SES_REGION)
    return ses.New(session.New(), sesConfig), nil
}