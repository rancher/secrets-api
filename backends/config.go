package backends

type Configs struct {
	EncryptionKeyPath string
}

func NewConfig() *Configs {
	return &Configs{}
}

func SetBackendConfigs(config *Configs) error {
	runtimeConfigs = config
	return nil
}
