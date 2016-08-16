package auth

type Server struct {
    // The database model operation
    Storage Storage
    Config  ServerConfig
}

type ServerConfig struct {
    SES_ACCESS_KEY            string
    SES_SECRET_KEY            string
    SES_REGION                string
    VerificationEmailTemplate VerificationEmailTemplate
}

type VerificationEmailTemplate struct {
    Subject string
    Body    string
    Source  string
}

func NewServer(storage Storage, config ServerConfig) Server {
    return Server{
        Storage: storage,
        Config:  config,
    }
}