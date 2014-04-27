<?php namespace k\Auth;

use Illuminate\Http\Request;
use k\Auth\Strategy\Standard as StandardStrategy;
use k\Auth\Strategy\OAuth as OAuthStrategy;
use k\Auth\Contracts\UserInterface as User;
use k\Auth\Contracts\HttpClientInterface as HttpClient;
use Illuminate\Session\Store as SessionStore;
use Log;

class Manager {

	const sessionKey = 'auth.identity';

	protected $standardAuthenticator;
	protected $oAuthAuthenticator;
	
	protected $config;
	protected $scope;
	protected $httpClient;
	protected $sessionStore;
	protected $userRepository;

	protected $keyUsageMarked = false;

	public function __construct(Config $config, Scope $scope, HttpClient $httpClient, SessionStore $sessionStore, $userRepository = null)
	{
		$this->config = $config;
		$this->scope = $scope;
		$this->httpClient = $httpClient;
		$this->sessionStore = $sessionStore;
		$this->userRepository = $userRepository;
	}

	protected function markKeyUsage()
	{
		$this->keyUsageMarked = true;
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
			$this->loginUser($user);
			return true;
		}
		else
		{
			return false;
		}
	}

	public function loginUser(User $user)
	{
		$this->sessionStore->regenerate();
		
		$this->scope->setAuthenticated(true);

		$this->sessionStore->put(static::sessionKey, new Identity($user->getAuthIdentifier()));
	}

	/////////////////////////////////
	
	public function check(Request $req)
	{
		if(! $this->sessionStore->has(static::sessionKey) and $req->headers->has($this->config->getApiKeyHeaderField()))
		{
			$apiKey = $req->headers->get($this->config->getApiKeyHeaderField());

			// now load the session for this api-key
			$this->sessionStore->setId($apiKey);
			$this->sessionStore->start();
		}

		if($identity = $this->sessionStore->get(static::sessionKey))
		{
			return $this->checkIdentity($identity);
		}
		else
		{
			return false;
		}
	}

	protected function checkIdentity(Identity $identity)
	{
		if($this->scope->getUser() and $this->scope->getUser() instanceof User)
		{
			return true;
		}

		if($user = $this->userRepository->findByAuthIdentifier($identity->getValue()) and $user instanceof User)
		{
			$this->setupScope($user, $identity);
			return true;
		}
		else
		{
			return false;
		}
	}

	protected function setupScope(User $user, Identity $identity)
	{
		if($this->keyUsageMarked)
		{
			return;
		}
		
		// if key usage limit is set to 0, it means there is no limit
		if($this->config->getKeyUsageLimit() === 0)
		{		
			$this->scope->setUser($user);
		}
		else
		{
			$identity->incrementUsageCount();

			if($identity->getUsageCount() > $this->config->getKeyUsageLimit())
			{
				$this->sessionStore->migrate(true);

				$refreshedKey = $this->sessionStore->getId();
				
				$this->scope->setRefreshedKey($refreshedKey);
				$this->scope->setUser($user);
			}
			else
			{
				$this->scope->setUser($user);
			}
		}

		$this->markKeyUsage();
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

		$this->sessionStore->forget(static::sessionKey);

		return true;
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


	///////////////////////////////
	
	public function processResponse($res)
	{

		if($this->scope->getAuthenticated())
		{
			$res->headers->set(
				$this->config->getApiKeyHeaderField(),
				$this->sessionStore->getId()
			);
		}

		if($this->scope->getRefreshedKey())
		{
			$res->headers->set(
				$this->config->getRefreshedApiKeyHeaderField(),
				$this->sessionStore->getId()
			);
		}

		if($this->scope->getLoggedOut())
		{
			$res->headers->remove($this->config->getApiKeyHeaderField());
			$res->headers->remove($this->config->getRefreshedApiKeyHeaderField());
		}
	}

}
