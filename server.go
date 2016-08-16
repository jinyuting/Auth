package auth

type Server struct {
    // The database model operation
    Storage Storage
    Config  ServerConfig
}

type ServerConfig struct {
    PasswordSalt               string
    TokenExpire                int64
    SesConfig                  SesConfig
    VerificationEmailTemplate  EmailTemplate
    ResetPasswordEmailTemplate EmailTemplate
}

type EmailTemplate struct {
    Subject string
    Body    string
    Source  string
}

type SesConfig struct {
    SES_ACCESS_KEY string
    SES_SECRET_KEY string
    SES_REGION     string
}

func NewServer(storage Storage, config ServerConfig) *Server {
    return &Server{
        Storage: storage,
        Config:  config,
    }
}