<?php namespace k\Auth;

class Config {

	protected $settings = array();

	public function __construct(array $settings = array())
	{
		$this->settings = $settings;
	}

	public function getKeyUsageLimit()
	{
		return array_get($this->settings, 'key-usage-limit');
	}

	public function getOAuthProviderField()
	{
		return array_get($this->settings, 'oauth-provider-field');
	}

	public function getOAuthTokenField()
	{
		return array_get($this->settings, 'oauth-token-field');
	}

	public function getUserCredentialsField()
	{
		return array_get($this->settings, 'user-credentials-field');
	}

	public function getUserPasswordField()
	{
		return array_get($this->settings, 'user-password-field');
	}

	public function getApiKeyHeaderField()
	{
		return array_get($this->settings, 'headers.api-key');
	}

	public function getRefreshedApiKeyHeaderField()
	{
		return array_get($this->settings, 'headers.refreshed-api-key');
	}

	public function getOAuthClientId($provider)
	{
		return array_get($this->settings, 'oauth.'.$provider.'.client-id');
	}

	public function getOAuthClientSecret($provider)
	{
		return array_get($this->settings, 'oauth.'.$provider.'.client-secret');
	}

	public function getLoginUri()
	{
		return array_get($this->settings, 'login-uri');
	}

}