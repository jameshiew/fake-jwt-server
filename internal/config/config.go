package config

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const envPrefix = "FAKE_JWT_SERVER"

type Config struct {
	DefaultIssuer           string
	DefaultSubject          string
	DefaultAudience         string
	DefaultScope            string
	DefaultAuthorizingParty string
	GenerateRSAKey          bool
}

const (
	defaultIssuer           = "http://localhost:8080/"
	defaultSubject          = "auth0|fb8618e6-8639-454d-9f94-4496b0b224a8"
	defaultAudience         = "http://localhost:3000"
	defaultScope            = "openid profile email"
	defaultAuthorizingParty = "example-azp"
	generateRSAKey          = false
)

func Default() Config {
	return Config{
		DefaultIssuer:           defaultIssuer,
		DefaultSubject:          defaultSubject,
		DefaultAudience:         defaultAudience,
		DefaultScope:            defaultScope,
		DefaultAuthorizingParty: defaultAuthorizingParty,
		GenerateRSAKey:          generateRSAKey,
	}
}

// Load populates a `Config` from the environment and config file (if present), using default values where no explicit configuration values are provided.
func Load() (Config, error) {
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()

	viper.SetDefault(DefaultIssuerKey, defaultIssuer)
	viper.SetDefault(DefaultSubjectKey, defaultSubject)
	viper.SetDefault(DefaultAudienceKey, defaultAudience)
	viper.SetDefault(DefaultScopeKey, defaultScope)
	viper.SetDefault(DefaultAuthorizingPartyKey, defaultAuthorizingParty)
	viper.SetDefault(GenerateRSAKeyKey, false)

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Info("No config found, will use defaults")
		} else {
			return Config{}, err
		}
	}
	return Config{
		DefaultIssuer:           viper.GetString(DefaultIssuerKey),
		DefaultSubject:          viper.GetString(DefaultSubjectKey),
		DefaultAudience:         viper.GetString(DefaultAudienceKey),
		DefaultScope:            viper.GetString(DefaultScopeKey),
		DefaultAuthorizingParty: viper.GetString(DefaultAuthorizingPartyKey),
		GenerateRSAKey:          viper.GetBool(GenerateRSAKeyKey),
	}, nil
}
