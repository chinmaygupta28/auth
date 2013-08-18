<?php namespace k\Auth\HttpClient;

use k\Auth\Contracts\HttpClientInterface;
use Guzzle\Http;
use k\Auth\Config;

class Guzzle implements HttpClientInterface {

	protected $config;
	protected $guzzle;

	public function __construct(Config $config, Http\Client $guzzle)
	{
		$this->config = $config;
		$this->guzzle = $guzzle;
	}

	protected function facebookClient()
	{
		$this->guzzle->setBaseUrl(HttpClientInterface::facebookApiOrigin);
		return $this->guzzle;
	}

	/**
	 * given a fb-token, fetches a long lived fb-token
	 * @param  string $token
	 * @param  string $clientId
	 * @param  string $clientSecret
	 * @return array
	 */
	public function fetchLongLivedFacebookToken($token, $clientId, $clientSecret)
	{
		try
		{
			$req = $this->facebookClient()->get('/oauth/access_token', [], [
					'query' => [
						'grant_type' => 'fb_exchange_token',
						'client_id' => $this->config->getOAuthClientId('facebook'),
						'client_secret' => $this->config->getOAuthClientSecret('facebook'),
						'fb_exchange_token' => $token
					]
				]);

			return json_decode($req->send()->getBody(true), true);
		}
		catch(Http\Exception\HttpException $e)
		{
			return [];
		}
	}

	/**
	 * Given a token, fetch user data from facebook
	 * @param  string $token
	 * @return array
	 */
	public function fetchFacebookUserData($token)
	{
		try
		{
			$req = 	$this->facebookClient()->get('/me', [], [
					'query' => ['access_token' => $token]
				]);

			return json_decode($req->send()->getBody(true), true);
		}
		catch(Http\Exception\HttpException $e)
		{
			return [];
		}
	}

}