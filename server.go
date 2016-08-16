package auth

type Server struct {
    // The database model operation
    Storage Storage
    MailBox MailBox
    Config  ServerConfig
}

type ServerConfig struct {
    // TODO
}

func NewServer(storage Storage, mailBox MailBox, config ServerConfig) Server {
    return Server{
        Storage: storage,
        MailBox: mailBox,
        Config:  config,
    }
}