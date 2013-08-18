<?php namespace k\Auth;

use Illuminate\Http\Request;
use k\Auth\Strategy\Standard as StandardStrategy;
use k\Auth\Strategy\OAuth as OAuthStrategy;
use k\Auth\IdentityStore\Item;
use k\Auth\Contracts\UserInterface as User;
use k\Auth\Contracts\HttpClientInterface as HttpClient;
use Illuminate\Session\Store as SessionStore;

class Manager {

	protected $standardAuthenticator;
	protected $oAuthAuthenticator;
	
	protected $config;
	protected $identityStore;
	protected $scope;
	protected $httpClient;
	protected $sessionStore;
	protected $userRepository;

	protected $sessionsEnabled = true;

	protected static $keyUsageMarked = false;

	public function __construct(Config $config,  IdentityStore $identityStore, Scope $scope, HttpClient $httpClient, SessionStore $sessionStore, $userRepository = null)
	{
		$this->config = $config;
		$this->identityStore = $identityStore;
		$this->scope = $scope;
		$this->httpClient = $httpClient;
		$this->sessionStore = $sessionStore;
		$this->userRepository = $userRepository;
	}

	protected static function markKeyUsage()
	{
		static::$keyUsageMarked = true;
	}

	///////////////////////////////////
	
	public function getSessionsEnabled()
	{
		return $this->sessionsEnabled;
	}
	
	public function disableSessions()
	{
		$this->sessionsEnabled = false;
		return $this;
	}

	public function enableSessions()
	{
		$this->sessionsEnabled = true;
		return $this;
	}

	public function setUserRepository($userRepository)
	{
		$this->userRepository = $userRepository;
		return $this;
	}

	public function getUserRepository()
	{
		return $this->userRepository;
	}

	public function getConfig()
	{
		return $this->config;
	}

	public function getIdentityStore()
	{
		return $this->identityStore;
	}

	public function getScope()
	{
		return $this->scope;
	}

	public function getHttpCient()
	{
		return $this->httpClient;
	}

	//////////////////////////

	public function hasOAuthCredentials(Request $req)
	{
		return $req->has($this->config->getOAuthProviderField())
		   and $req->has($this->config->getOAuthTokenField());
	}

	public function hasUserCredentialsAndPassword(Request $req)
	{
		return $req->has($this->config->getUserCredentialsField())
		   and $req->has($this->config->getUserPasswordField());
	}

	public function authenticate(Request $req)
	{
		if($this->hasOAuthCredentials($req))
		{
			$result = $this->getOAuthStrategy()->authenticate($req);
		}
		elseif($this->hasUserCredentialsAndPassword($req))
		{
			$result = $this->getStandardStrategy()->authenticate($req);
		}
		else
		{
			$result = false;
		}

		if($result and $user = $this->scope->getUser() and $user instanceof User)
		{
			$this->loginUser($user, $req);
			return true;
		}
		else
		{
			return false;
		}
	}

	public function loginUser(User $user, Request $req)
	{
		$key = $this->identityStore->generateRandomKey();
		$this->identityStore->put($key, new Item($user->getAuthIdentifier()));
		$this->scope->setApiKey($key);
		$this->scope->setAuthenticated(true);
	}

	/////////////////////////////////
	
	public function hasApiKeyInHeader(Request $req)
	{
		return $req->headers->has($this->config->getApiKeyHeaderField());
	}

	public function isApiKeyInSession()
	{
		return $this->sessionsEnabled
		   and $this->sessionStore->has($this->config->getApiKeySessionField())
		;
	}
	
	public function check(Request $req)
	{
		if($this->hasApiKeyInHeader($req))
		{
			$apiKey = $req->headers->get($this->config->getApiKeyHeaderField());
			$result = $this->checkApiKey($apiKey);
		}
		elseif($this->isApiKeyInSession())
		{
			$apiKey = $this->sessionStore->get($this->config->getApiKeySessionField());
			$result = $this->checkApiKey($apiKey);
		}
		else
		{
			$result = false;
		}

		return $result;
	}

	protected function checkApiKey($key)
	{
		if($this->scope->getUser() and $this->scope->getUser() instanceof User)
		{
			return true;
		}

		if(! $identifierItem = $this->identityStore->get($key))
		{
			return false;
		}

		$identifier = $identifierItem->getIdentity();

		if($user = $this->userRepository->findByAuthIdentifier($identifier) and $user instanceof User)
		{
			$this->setupScope($key, $user, $identifierItem);
			return true;
		}
		else
		{
			return false;
		}
	}

	protected function setupScope($key, User $user, Item $identityItem)
	{
		if(! static::$keyUsageMarked)
		{
			$identityItem->incrementUsageCount();

			if($identityItem->getUsageCount() > $this->config->getKeyUsageLimit())
			{
				$refreshedKey = $this->identityStore->refresh($key);
				$this->scope->setRefreshedKey($refreshedKey);
				$this->scope->setKey(null);
				$this->scope->setUser($user);
			}
			else
			{
				$this->scope->setKey($key);
				$this->scope->setUser($user);
			}

			static::markKeyUsage();
		}
	}

	////////////////////////////
	
	public function register(Request $req)
	{
		if($this->hasOAuthCredentials($req))
		{
			$result = $this->getOAuthStrategy()->register($req);
		}
		elseif($this->hasUserCredentialsAndPassword($req))
		{
			$result = $this->getStandardStrategy()->register($req);
		}
		else
		{
			$result = false;
		}

		if($result and $user = $this->scope->getUser() and $user instanceof User)
		{
			$this->loginUser($user, $req);
			return true;
		}
		else
		{
			return false;
		}
	}

	//////////////////////////////
	
	public function logout(Request $req)
	{
		if(! $this->check($req))
		{
			return false;
		}
		
		if($this->hasApiKeyInHeader($req))
		{
			$apiKey = $req->headers->get($this->config->getApiKeyHeaderField());
		}
		elseif($this->isApiKeyInSession())
		{
			$apiKey = $this->sessionStore->get($this->config->getApiKeySessionField());
		}

		$this->logoutApiKey($apiKey);

		return true;
	}

	protected function logoutApiKey($key)
	{
		$this->scope->clear();
		$this->scope->setLoggedOut(true);
		$this->identityStore->forget($key);
	}


	/////////////////////////////

	protected function getOAuthStrategy()
	{
		if($this->oAuthAuthenticator) return $this->oAuthAuthenticator;

		return $this->oAuthAuthenticator = new OAuthStrategy(
												$this->config, $this->userRepository,
												$this->httpClient, $this->scope
											);
	}

	protected function getStandardStrategy()
	{
		if($this->standardAuthenticator) return $this->standardAuthenticator;

		return $this->standardAuthenticator = new StandardStrategy(
												$this->config, $this->userRepository,
												$this->scope
											);
	}


	/////////////////////////////////
	
	public function processResponse($res)
	{
		if($this->scope->getAuthenticated())
		{
			$res->headers->set(
				$this->config->getApiKeyHeaderField(),
				$this->scope->getApiKey()
			);

			if($this->sessionsEnabled)
			{
				$this->sessionStore->put(
					$this->config->getApiKeySessionField(),
					$this->scope->getApiKey()
				);
			}
		}

		if($this->scope->getRefreshedKey())
		{
			$res->headers->set(
				$this->config->getRefreshedApiKeyHeaderField(),
				$this->scope->getRefreshedKey()
			);

			if($this->sessionsEnabled)
			{
				$this->sessionStore->put(
					$this->config->getApiKeySessionField(),
					$this->scope->getRefreshedKey()
				);
			}
		}

		if($this->scope->getLoggedOut())
		{
			$res->headers->remove($this->config->getApiKeyHeaderField());
			$res->headers->remove($this->config->getRefreshedApiKeyHeaderField());

			if($this->sessionsEnabled)
			{
				$this->sessionStore->forget($this->config->getApiKeySessionField());
			}
		}
	}

}