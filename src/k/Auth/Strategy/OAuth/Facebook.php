<?php namespace k\Auth\Strategy\OAuth;

use k\Auth\Contracts\Facebook\UserRepositoryInterface as UserRepository;
use k\Auth\Contracts\Facebook\UserInterface as User;
use k\Auth\Contracts\HttpClientInterface as HttpClient;
use k\Auth\Scope;
use k\Auth\Config;

class Facebook {

	protected $config;
	protected $userRepository;
	protected $httpClient;
	protected $scope;

	const graphApiOrigin = 'https://graph.facebook.com';

	public function __construct(Config $config, UserRepository $userRepository, HttpClient $httpClient, Scope $scope)
	{
		$this->config = $config;
		$this->userRepository = $userRepository;
		$this->httpClient = $httpClient;
		$this->scope = $scope;
	}

	protected function fetchLongLivedToken($token)
	{
		$fbClientId = $this->config->getOAuthClientId('facebook');
		$fbClientSecret = $this->config->getOAuthClientSecret('facebook');

		$data = $this->httpClient->fetchLongLivedFacebookToken($token, $fbClientId, $fbClientSecret);

		return isset($data->access_token) ? $data->access_token : null;
	}

	protected function fetchUserData($token)
	{
		return $this->httpClient->fetchFacebookUserData($token);
	}

	public function authenticate($token)
	{
		$fbData = $this->fetchUserData($token);

		if($user = $this->userRepository->findByFacebookData($fbData) and $user instanceof User)
		{
			$longLivedToken = $this->fetchLongLivedToken($token);
			$user->setFacebookToken($longLivedToken);
			
			$this->scope->setUser($user);

			return true;
		}

		return false;
	}

	public function register($token)
	{
		$fbData = $this->fetchUserData($token);

		if($user = $this->userRepository->createFromFacebookData($fbData) and $user instanceof User)
		{
			$longLivedToken = $this->fetchLongLivedToken($token);
			$user->setFacebookToken($longLivedToken);

			$this->scope->setUser($user);

			return true;
		}

		return false;
	}

}