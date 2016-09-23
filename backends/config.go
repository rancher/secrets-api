package backends

type Configs struct {
	VaultToken        string
	VaultURL          string
	EncryptionKeyPath string
}

func NewConfig() *Configs {
	return &Configs{}
}

func SetBackendConfigs(config *Configs) error {
	runtimeConfigs = config
	return nil
}
